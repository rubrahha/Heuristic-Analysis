"""
bridge.py v3.1 — Enterprise‑grade two‑phase folder scanner + concurrent single‑file.

Folder scanning pipeline:
  Phase 1 : C++ only (collect all files, scores, indicators)
  Phase 2 : AI batch inference only on files that require deeper analysis

Single‑file scanning:
  Concurrent C++ + AI (no change from v3.0)
"""
from __future__ import annotations

import mmap
import os
import re
import json
import math
import logging
import signal
import subprocess
import threading
import hashlib
import time
import uuid
import datetime
import warnings
import sys
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.utils.parallel")
from collections import OrderedDict

# Safe import for PE analysis
try:
    import pefile
except ImportError:
    pefile = None

from concurrent.futures import (
    Future,
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    as_completed,
    wait,
    FIRST_COMPLETED,
)
from logging.handlers import RotatingFileHandler
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterator, List, Optional, Tuple, Set

import lightgbm as lgb
import numpy as np
import logging

# 🚨 FIX: Gag the EMBER logger to stop the LIEF version spam
logging.getLogger("ember").setLevel(logging.ERROR)
logging.getLogger("ember.features").setLevel(logging.ERROR)

# Import the EMBER extractor (ensure features.py is in the same folder)
from ember.features import PEFeatureExtractor

__version__ = "3.1.0"

# ── Bloom filter (pure‑Python, no extra deps) ──────────────────────────────────

class _BloomFilter:
    """
    Space‑efficient probabilistic set.
    False‑positive rate ≈ 1% at the default k/m values.
    Used as a fast pre‑check before the heavier SHA‑256 LRU lookup.
    """
    __slots__ = ("_bits", "_k", "_m")

    def __init__(self, capacity: int = 200_000, fp_rate: float = 0.01) -> None:
        self._m = self._optimal_m(capacity, fp_rate)
        self._k = self._optimal_k(self._m, capacity)
        self._bits = bytearray(self._m // 8 + 1)

    @staticmethod
    def _optimal_m(n: int, p: float) -> int:
        return max(8, int(-n * math.log(p) / (math.log(2) ** 2)))

    @staticmethod
    def _optimal_k(m: int, n: int) -> int:
        return max(1, round(m / n * math.log(2)))

    def _hashes(self, item: str) -> List[int]:
        h1 = int(hashlib.md5(item.encode()).hexdigest(), 16)
        h2 = int(hashlib.sha1(item.encode()).hexdigest(), 16)
        return [(h1 + i * h2) % self._m for i in range(self._k)]

    def add(self, item: str) -> None:
        for pos in self._hashes(item):
            self._bits[pos // 8] |= (1 << (pos % 8))

    def __contains__(self, item: str) -> bool:
        return all(
            self._bits[pos // 8] & (1 << (pos % 8))
            for pos in self._hashes(item)
        )

    def bulk_add(self, items) -> None:
        for item in items:
            self.add(item)


# ── Structured JSON logging ────────────────────────────────────────────────────

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        d: Dict[str, Any] = {
            "ts":     self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level":  record.levelname,
            "thread": record.threadName,
            "logger": record.name,
            "pid":    os.getpid(),
            "msg":    record.getMessage(),
        }
        if record.exc_info:
            d["exc"] = self.formatException(record.exc_info)
        return json.dumps(d, ensure_ascii=False)


def _configure_logging() -> logging.Logger:
    logger = logging.getLogger("bridge")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    logger.addHandler(ch)
    try:
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        fh = RotatingFileHandler(
            log_dir / "bridge.jsonl",
            maxBytes=20 * 1024 * 1024,
            backupCount=10,
            encoding="utf-8",
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_JsonFormatter())
        logger.addHandler(fh)
    except Exception:
        pass
    return logger


log = _configure_logging()

# ── Paths ──────────────────────────────────────────────────────────────────────

if getattr(sys, 'frozen', False):
    # We are running inside PyInstaller
    _HERE = Path(sys._MEIPASS)                 # Where the AI model is hidden
    _RUNTIME_DIR = Path(sys.executable).parent # Where BrainEngine.exe is running from
    
    # Auto-detect the C++ engine sitting next to us (handles Tauri's renamed sidecars)
    _scanners = list(_RUNTIME_DIR.glob("Heuristic*.exe"))
    _scanners = [s for s in _scanners if "BrainEngine" not in s.name]
    CPP_SCANNER = str(_scanners[0]) if _scanners else str(_RUNTIME_DIR / "HeuristicScanner.exe")
else:
    # Standard Developer Mode
    _HERE       = Path(__file__).parent
    CPP_SCANNER = str(_HERE.parent / "scanner" / "build" / "HeuristicScanner.exe")

MODEL_PATH  = _HERE / "models" / "ember_lightgbm.txt"
CONFIG_PATH = _HERE / "bridge_config.json"
# ───────────────────────────────────────────────────────────────────────────────

# ── Default config ─────────────────────────────────────────────────────────────
_DEFAULT_CONFIG: Dict[str, Any] = {
    # ── Scoring weights ────────────────────────────────────────────────────
    "cpp_weight":                   0.45,
    "ai_weight":                    0.55,
    "ai_override_threshold":        20,
    "ai_veto_threshold":            55,
    "ai_veto_hard_cap":             15,
    "detection_threshold":          0.5,

    # ── False‑negative floors ──────────────────────────────────────────────
    "trusted_path_score_cap":       30,
    "trusted_publisher_score_cap":  15,
    "hard_floor_entropy":           7.5,
    "hard_floor_score":             45,
    "high_risk_feature_floor":      60,
    "min_score_unsigned_network":   25,
    "bypass_trust_min_indicators":  3,
    "ai_veto_max_indicators":       2,
    "ai_below_threshold_weight":    0.70,

    # ── Ensemble support ───────────────────────────────────────────────────
    "ensemble_members":             [],

    # ── Concurrency ────────────────────────────────────────────────────────
    "max_concurrent_scans":         0,      # 0 → auto (4 × cpu_count)
    "ai_workers":                   0,      # 0 → auto (cpu_count)
    "feature_workers":              0,      # 0 → auto (cpu_count // 2, min 2)
    "cpp_timeout_seconds":          30,
    "ai_timeout_seconds":           20,
    "dir_cpp_timeout":              300,

    # ── Batch inference ────────────────────────────────────────────────────
    "batch_size":                   64,
    "batch_flush_ms":               50,

    # ── Caching ────────────────────────────────────────────────────────────
    "result_cache_size":            4096,
    "result_cache_ttl_seconds":     300,
    "hash_cache_size":              8192,

    # ── Redis (optional distributed cache) ────────────────────────────────
    "redis_url":                    "",
    "redis_ttl_seconds":            3600,
    "redis_key_prefix":             "bridge:scan:",

    # ── Circuit breaker ────────────────────────────────────────────────────
    "cpp_cb_fail_threshold":        5,
    "cpp_cb_reset_seconds":         60,

    # ── Priority queue ─────────────────────────────────────────────────────
    "high_priority_path_patterns":  [
        r"\\temp\\", r"\\tmp\\", r"\\appdata\\", r"\\downloads\\",
        r"\\programdata\\", r"\\users\\public\\",
    ],
}


def _load_config() -> Dict[str, Any]:
    cfg = dict(_DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            user_cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            cfg.update({k: v for k, v in user_cfg.items() if k in cfg})
            log.info("Loaded config from %s", CONFIG_PATH)
        except Exception as e:
            log.warning("Config load failed (%s): using defaults", e)
    return cfg


_cfg = _load_config()

# ── Derive hardware‑aware worker counts ────────────────────────────────────────
_CPUS = os.cpu_count() or 4

def _resolve(key: str, fallback: int) -> int:
    val = int(_cfg[key])
    return fallback if val <= 0 else val

MAX_CONCURRENT  = _resolve("max_concurrent_scans", max(16, _CPUS * 4))
AI_WORKERS      = _resolve("ai_workers",           max(4,  _CPUS))
FEATURE_WORKERS = _resolve("feature_workers",      max(2,  _CPUS // 2))
BATCH_SIZE      = int(_cfg["batch_size"])
BATCH_FLUSH_MS  = float(_cfg["batch_flush_ms"]) / 1000.0

# Scoring
CPP_W                       = float(_cfg["cpp_weight"])
AI_W                        = float(_cfg["ai_weight"])
AI_OVERRIDE                 = int(_cfg["ai_override_threshold"])
AI_VETO_THRESHOLD           = int(_cfg["ai_veto_threshold"])
AI_VETO_HARD_CAP            = int(_cfg["ai_veto_hard_cap"])
AI_BELOW_THRESHOLD_WEIGHT   = float(_cfg["ai_below_threshold_weight"])
_DEFAULT_THRESHOLD          = float(_cfg["detection_threshold"])

# Floors
TRUSTED_PATH_SCORE_CAP      = int(_cfg["trusted_path_score_cap"])
TRUSTED_PUB_SCORE_CAP       = int(_cfg["trusted_publisher_score_cap"])
HARD_FLOOR_ENTROPY          = float(_cfg["hard_floor_entropy"])
HARD_FLOOR_SCORE            = int(_cfg["hard_floor_score"])
HIGH_RISK_FEATURE_FLOOR     = int(_cfg["high_risk_feature_floor"])
MIN_SCORE_UNSIGNED_NETWORK  = int(_cfg["min_score_unsigned_network"])
BYPASS_TRUST_MIN_INDICATORS = int(_cfg["bypass_trust_min_indicators"])
AI_VETO_MAX_INDICATORS      = int(_cfg["ai_veto_max_indicators"])

# Timeouts
CPP_TIMEOUT     = int(_cfg["cpp_timeout_seconds"])
AI_TIMEOUT      = int(_cfg["ai_timeout_seconds"])
DIR_CPP_TIMEOUT = int(_cfg["dir_cpp_timeout"])

# Cache
RESULT_CACHE_SIZE = int(_cfg["result_cache_size"])
RESULT_CACHE_TTL  = int(_cfg["result_cache_ttl_seconds"])
HASH_CACHE_SIZE   = int(_cfg["hash_cache_size"])

# Redis
REDIS_URL        = str(_cfg["redis_url"])
REDIS_TTL        = int(_cfg["redis_ttl_seconds"])
REDIS_PREFIX     = str(_cfg["redis_key_prefix"])

_scan_semaphore = threading.Semaphore(MAX_CONCURRENT)

# Pre‑compiled priority path regexes
_PRIORITY_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE)
    for p in _cfg.get("high_priority_path_patterns", [])
]

# ── OS paths ───────────────────────────────────────────────────────────────────
_SYS_DRIVE      = os.environ.get("SystemDrive",       "C:").lower()
_PROG_FILES     = os.environ.get("ProgramFiles",      r"C:\Program Files").lower()
_PROG_FILES_X86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower()
_SYS_ROOT       = os.environ.get("SystemRoot",        r"C:\Windows").lower()

TRUSTED_PREFIXES: Tuple[str, ...] = (
    _PROG_FILES, _PROG_FILES_X86,
    rf"{_SYS_ROOT}\system32",    rf"{_SYS_ROOT}\syswow64",
    rf"{_SYS_ROOT}\sysnative",   rf"{_SYS_ROOT}\winsxs",
    rf"{_SYS_ROOT}\microsoft.net", rf"{_SYS_ROOT}\assembly",
    rf"{_SYS_ROOT}\servicing",   rf"{_SYS_ROOT}\installer",
    rf"{_SYS_ROOT}\softwaredistribution",
    rf"{_SYS_ROOT}\boot",        rf"{_SYS_ROOT}\system",
    rf"{_PROG_FILES}\dotnet",    rf"{_PROG_FILES_X86}\dotnet",
    rf"{_PROG_FILES}\microsoft visual studio",
    rf"{_PROG_FILES_X86}\microsoft visual studio",
    rf"{_PROG_FILES_X86}\windows kits", rf"{_PROG_FILES}\windows kits",
    rf"{_PROG_FILES}\microsoft office",
    rf"{_PROG_FILES_X86}\microsoft office",
    rf"{_PROG_FILES}\windows defender",
    rf"{_PROG_FILES_X86}\windows defender",
    rf"{_PROG_FILES}\steam",     rf"{_PROG_FILES_X86}\steam",
    rf"{_PROG_FILES}\epic games",rf"{_PROG_FILES_X86}\epic games",
    rf"{_PROG_FILES}\python",    rf"{_PROG_FILES_X86}\python",
    rf"{_PROG_FILES}\nodejs",    rf"{_PROG_FILES_X86}\nodejs",
    rf"{_PROG_FILES}\git",       rf"{_PROG_FILES_X86}\git",
    rf"{_PROG_FILES}\google\chrome",
    rf"{_PROG_FILES_X86}\google\chrome",
    rf"{_SYS_DRIVE}\mingw",      rf"{_SYS_DRIVE}\mingw-w64",
)

TRUSTED_PUBLISHERS = frozenset({
    "Microsoft Corporation", "Microsoft Windows", "Intel Corporation",
    "Oracle America, Inc.", "Adobe Inc.", "Apple Inc.", "Google LLC",
    "NVIDIA Corporation", "Advanced Micro Devices, Inc.", "VMware, Inc.",
    "GitHub, Inc.", "Mozilla Corporation", "Autodesk, Inc.", "JetBrains s.r.o.",
    "The Qt Company", "Alexander Roshal", "Igor Pavlov", "Notepad++",
    "Python Software Foundation", "Node.js Foundation", "Simon Tatham",
    "The Wireshark Foundation, Inc.", "OBS Project", "VideoLAN",
    "Brave Software, Inc.", "Opera Software ASA", "Discord Inc.",
    "Slack Technologies, Inc.", "Zoom Video Communications, Inc.",
    "TeamViewer GmbH", "AnyDesk Software GmbH", "Docker Inc.",
})
TRUSTED_PUBLISHER_KEYWORDS = frozenset({
    "microsoft", "intel", "oracle", "sun", "adobe", "apple", "google",
    "nvidia", "amd", "vmware", "github", "mozilla", "autodesk", "jetbrains",
    "qt", "winrar", "rar", "7-zip", "notepad++", "python", "node", "putty",
    "wireshark", "obs", "vlc", "firefox", "chrome", "brave", "opera",
    "discord", "slack", "zoom", "teamviewer", "anydesk", "docker",
})

SCAN_EXTS = frozenset({
    ".exe", ".dll", ".scr", ".sys", ".ocx", ".drv", ".cpl",
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
})

_RE_SCORE      = re.compile(r"SCORE:(\d+)")
_RE_INDICATORS = re.compile(r">>\s*(.+)")

# ── Metrics ────────────────────────────────────────────────────────────────────

class _Metrics:
    __slots__ = (
        "_lock", "scans_total", "scans_clean", "scans_suspicious",
        "scans_high_risk", "scans_error", "cache_hits", "cache_misses",
        "redis_hits", "redis_misses", "cpp_timeouts", "ai_errors",
        "trust_bypassed", "batch_flushes", "coalesced_hits",
        "ipc_reconnects",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        for s in self.__slots__:
            if not s.startswith("_"):
                setattr(self, s, 0)

    def inc(self, name: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, name, getattr(self, name) + n)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {s: getattr(self, s) for s in self.__slots__ if not s.startswith("_")}


metrics = _Metrics()

# ── LRU + TTL result cache ─────────────────────────────────────────────────────

class _TTLCache:
    def __init__(self, maxsize: int, ttl: float) -> None:
        self._maxsize = maxsize
        self._ttl     = ttl
        self._data: OrderedDict[str, Tuple[float, Any]] = OrderedDict()
        self._lock    = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            ts, val = entry
            if time.monotonic() - ts > self._ttl:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return val

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = (time.monotonic(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


_result_cache = _TTLCache(RESULT_CACHE_SIZE, RESULT_CACHE_TTL)

# ── SHA‑256 LRU cache (content‑addressable, no TTL) ───────────────────────────

class _HashLRU:
    """Thread‑safe LRU for SHA‑256 results keyed by file path."""

    def __init__(self, maxsize: int) -> None:
        self._maxsize = maxsize
        self._data: OrderedDict[str, str] = OrderedDict()
        self._lock   = threading.Lock()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            val = self._data.get(key)
            if val:
                self._data.move_to_end(key)
            return val

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)


_hash_lru = _HashLRU(HASH_CACHE_SIZE)

# ── Optional Redis distributed cache ──────────────────────────────────────────

_redis_client: Optional[Any] = None
_redis_lock    = threading.Lock()
_redis_ok      = False


def _get_redis() -> Optional[Any]:
    global _redis_client, _redis_ok
    if not REDIS_URL:
        return None
    if _redis_ok and _redis_client is not None:
        return _redis_client
    with _redis_lock:
        if _redis_ok and _redis_client is not None:
            return _redis_client
        try:
            import redis  # type: ignore
            _redis_client = redis.from_url(REDIS_URL, socket_connect_timeout=2,
                                           socket_timeout=1, decode_responses=True)
            _redis_client.ping()
            _redis_ok = True
            log.info("Redis cache connected: %s", REDIS_URL)
        except Exception as e:
            log.warning("Redis unavailable (%s) — using local cache only", e)
            _redis_ok = False
            _redis_client = None
    return _redis_client if _redis_ok else None


def _redis_get(cache_key: str) -> Optional[dict]:
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(REDIS_PREFIX + cache_key)
        if raw:
            metrics.inc("redis_hits")
            return json.loads(raw)
        metrics.inc("redis_misses")
    except Exception:
        pass
    return None


def _redis_set(cache_key: str, value: dict) -> None:
    r = _get_redis()
    if r is None:
        return
    try:
        r.setex(REDIS_PREFIX + cache_key, REDIS_TTL, json.dumps(value, default=str))
    except Exception:
        pass


# ── Circuit breaker ────────────────────────────────────────────────────────────

class _CircuitBreaker:
    CLOSED = "CLOSED"; OPEN = "OPEN"; HALF_OPEN = "HALF_OPEN"

    def __init__(self, fail_threshold: int, reset_seconds: float) -> None:
        self._fail_threshold  = fail_threshold
        self._reset_seconds   = reset_seconds
        self._failures        = 0
        self._last_failure_ts = 0.0
        self._state           = self.CLOSED
        self._lock            = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    def call_allowed(self) -> bool:
        with self._lock:
            if self._state == self.CLOSED:
                return True
            if self._state == self.OPEN:
                if time.monotonic() - self._last_failure_ts >= self._reset_seconds:
                    self._state = self.HALF_OPEN
                    return True
                return False
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state    = self.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failures       += 1
            self._last_failure_ts = time.monotonic()
            if self._failures >= self._fail_threshold:
                if self._state != self.OPEN:
                    log.warning("Circuit breaker OPEN: C++ scanner paused for %ds",
                                self._reset_seconds)
                self._state = self.OPEN


_cpp_cb = _CircuitBreaker(
    fail_threshold = int(_cfg["cpp_cb_fail_threshold"]),
    reset_seconds  = float(_cfg["cpp_cb_reset_seconds"]),
)

# ── Persistent C++ IPC scanner ─────────────────────────────────────────────────

class _IpcScanner:
    """
    Persistent IPC bridge to HeuristicScanner.exe --server mode.
    Thread‑safe: uses a per‑request condition variable for result delivery.
    """

    def __init__(self) -> None:
        self._proc:    Optional[subprocess.Popen] = None
        self._lock     = threading.Lock()    # Protects process handles + _pending
        self._pending: Dict[str, threading.Event] = {}
        self._results: Dict[str, Tuple[Optional[int], List[str]]] = {}
        self._reader:  Optional[threading.Thread] = None
        self._alive    = False

    def _spawn(self) -> bool:
        """Start scanner process. Returns True on success."""
        if not os.path.exists(CPP_SCANNER):
            return False
        try:
            self._proc = subprocess.Popen(
                [CPP_SCANNER, "--server"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace",
                bufsize=1, creationflags=_nowin(),
            )
            self._alive = True
            self._reader = threading.Thread(
                target=self._read_loop, daemon=True, name="IpcReader"
            )
            self._reader.start()
            log.info("IPC scanner started (pid=%d)", self._proc.pid)
            return True
        except Exception as e:
            log.warning("IPC scanner spawn failed: %s", e)
            return False

    def _read_loop(self) -> None:
        try:
            for raw in self._proc.stdout:
                line = raw.strip()
                if not line:
                    continue
                
                # --- THIS DEBUG LINE PROVES C++ IS WORKING ---
                #print(f"\n[C++ ENGINE] {line}\n", flush=True)

                try:
                    obj   = json.loads(line)
                    fp_raw = obj.get("file") or obj.get("path", "")
                    
                    # Force lowercase to guarantee the dictionary matches!
                    fp_safe = fp_raw.lower().replace("/", "\\")
                    
                    score = obj.get("score")
                    inds  = obj.get("indicators") or []
                    with self._lock:
                        self._results[fp_safe] = (score, inds)
                        ev = self._pending.pop(fp_safe, None)
                    if ev:
                        ev.set()
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass
        finally:
            self._alive = False
            with self._lock:
                for ev in self._pending.values():
                    ev.set()
                self._pending.clear()

    def scan(self, fp: str) -> Tuple[Optional[int], List[str]]:
        if not self._alive:
            with self._lock:
                if not self._alive:
                    if not self._spawn():
                        return _cpp_file_fallback(fp)

        # Force lowercase before saving the waiter!
        fp_safe = fp.lower().replace("/", "\\")
        ev = threading.Event()
        
        try:
            with self._lock:
                self._pending[fp_safe] = ev
                self._proc.stdin.write(fp + "\n")
                self._proc.stdin.flush()
        except Exception as e:
            with self._lock:
                self._pending.pop(fp_safe, None)
            self._reconnect()
            return _cpp_file_fallback(fp)

        signaled = ev.wait(timeout=CPP_TIMEOUT)
        with self._lock:
            result = self._results.pop(fp_safe, None)

        if not signaled or result is None:
            metrics.inc("cpp_timeouts")
            _cpp_cb.record_failure()
            return None, ["C++ scan timed out"]

        _cpp_cb.record_success()
        return result
    
    def _reconnect(self) -> bool:
        metrics.inc("ipc_reconnects")
        log.warning("IPC scanner reconnecting…")
        self._alive = False
        if self._proc:
            try:
                self._proc.kill()
            except Exception:
                pass
            self._proc = None
        return self._spawn()

    
    def close(self) -> None:
        self._alive = False
        if self._proc:
            try:
                self._proc.stdin.close()
                self._proc.wait(timeout=5)
            except Exception:
                pass


_ipc_scanner = _IpcScanner()


def _nowin() -> int:
    return 0x08000000 if os.name == "nt" else 0


def _cpp_file_fallback(fp: str) -> Tuple[Optional[int], List[str]]:
    """Per‑file subprocess fallback when IPC is unavailable."""
    if not os.path.exists(CPP_SCANNER):
        return None, ["C++ scanner not found — run build.bat first"]
    if not _cpp_cb.call_allowed():
        return None, [f"C++ circuit breaker {_cpp_cb.state}"]
    try:
        r = subprocess.run(
            [CPP_SCANNER, "--file", fp],
            capture_output=True, text=True,
            timeout=CPP_TIMEOUT, creationflags=_nowin(),
            encoding="utf-8", errors="replace",
        )
        _cpp_cb.record_success()
        out   = r.stdout + r.stderr
        m     = _RE_SCORE.search(out)
        score = int(m.group(1)) if m else None
        inds  = [ln.strip() for ln in _RE_INDICATORS.findall(out)]
        return score, inds
    except subprocess.TimeoutExpired:
        metrics.inc("cpp_timeouts")
        _cpp_cb.record_failure()
        return None, ["C++ scan timed out"]
    except Exception as e:
        _cpp_cb.record_failure()
        return None, [f"C++ error: {e}"]


def _cpp_file(fp: str) -> Tuple[Optional[int], List[str]]:
    """Route to IPC scanner (preferred) or per‑file fallback."""
    if not _cpp_cb.call_allowed():
        return None, [f"C++ circuit breaker {_cpp_cb.state}"]
    return _ipc_scanner.scan(fp)


def _cpp_dir_stream(dp: str) -> Iterator[dict]:
    """Batch directory scan — uses separate process for bulk enumeration."""
    if not os.path.exists(CPP_SCANNER):
        return
    if not _cpp_cb.call_allowed():
        log.warning("C++ circuit breaker is %s — skipping directory scan", _cpp_cb.state)
        return
    proc: Optional[subprocess.Popen] = None
    deadline = time.monotonic() + DIR_CPP_TIMEOUT
    try:
        proc = subprocess.Popen(
            [CPP_SCANNER, "--dir", dp],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding="utf-8", errors="replace",
            bufsize=1, creationflags=_nowin(),
        )
        _cpp_cb.record_success()
        all_lines: List[str] = []
        first_line = ""

        for raw in proc.stdout:
            if time.monotonic() > deadline:
                return
            stripped = raw.strip()
            if stripped:
                first_line = stripped
                all_lines.append(stripped)
                break

        if not first_line:
            return

        if first_line.startswith("{"):
            try:
                obj = json.loads(first_line)
                if not obj.get("done") and (obj.get("file") or obj.get("path")):
                    yield obj
            except json.JSONDecodeError:
                pass
            for raw in proc.stdout:
                if time.monotonic() > deadline:
                    return
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if obj.get("done"):
                        break
                    if obj.get("file") or obj.get("path"):
                        yield obj
                except json.JSONDecodeError:
                    continue

        elif first_line.startswith("["):
            for raw in proc.stdout:
                if time.monotonic() > deadline:
                    return
                if raw.strip():
                    all_lines.append(raw.strip())
            try:
                items = json.loads("".join(all_lines))
                if isinstance(items, list):
                    for obj in items:
                        if isinstance(obj, dict) and (obj.get("file") or obj.get("path")):
                            yield obj
            except json.JSONDecodeError:
                pass

    except Exception as e:
        _cpp_cb.record_failure()
        log.error("_cpp_dir_stream error for %s: %s", dp, e)
    finally:
        if proc is not None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    pass


# ── Whitelist with Bloom filter ────────────────────────────────────────────────
_whitelist_lock:   threading.RLock  = threading.RLock()
_whitelist_hashes: Optional[frozenset] = None
_whitelist_bloom:  Optional[_BloomFilter] = None
_WHITELIST_FILE   = _HERE / "whitelist_hashes.json"


def _get_whitelist() -> Tuple[frozenset, _BloomFilter]:
    global _whitelist_hashes, _whitelist_bloom
    if _whitelist_hashes is not None:
        return _whitelist_hashes, _whitelist_bloom  # type: ignore[return-value]
    with _whitelist_lock:
        if _whitelist_hashes is not None:
            return _whitelist_hashes, _whitelist_bloom  # type: ignore[return-value]
        wl: Set[str] = set()
        if _WHITELIST_FILE.exists():
            try:
                data = json.loads(_WHITELIST_FILE.read_text(encoding="utf-8"))
                wl   = set(data.get("hashes", []))
                log.info("Loaded %d whitelist hashes", len(wl))
            except Exception as e:
                log.warning("Whitelist load failed: %s", e)
        _whitelist_hashes = frozenset(wl)
        _whitelist_bloom  = _BloomFilter(capacity=max(len(wl), 1000))
        _whitelist_bloom.bulk_add(wl)
    return _whitelist_hashes, _whitelist_bloom  # type: ignore[return-value]


def _in_whitelist(h: str) -> bool:
    """Two‑stage lookup: O(1) bloom filter then O(1) frozenset confirm."""
    if not h:
        return False
    wl_set, bloom = _get_whitelist()
    if h not in bloom:       # Definitely not in whitelist
        return False
    return h in wl_set       # Confirm (bloom can have false positives)


# ── Model / ensemble ───────────────────────────────────────────────────────────
_model_lock      = threading.RLock()
_models: List[Tuple[Any, float, float]] = []   # (model, weight, threshold)
_model_loaded    = False
_model_threshold = _DEFAULT_THRESHOLD

# Worker‑local model cache for ProcessPool children
_worker_models: Optional[List[Tuple[Any, float, float]]] = None


def _load_models_once() -> List[Tuple[Any, float, float]]:
    """Load the EMBER LightGBM model. Called once per process."""
    members: List[Tuple[Any, float, float]] = []
    
    if MODEL_PATH.exists():
        try:
            # Load LightGBM Booster
            mdl = lgb.Booster(model_file=str(MODEL_PATH))
            
            # EMBER typically requires a higher threshold (e.g., 0.83) for low FP rate
            thr = _DEFAULT_THRESHOLD if _DEFAULT_THRESHOLD != 0.5 else 0.83
            
            members.append((mdl, 1.0, thr))
            log.info("Loaded EMBER model (threshold=%.3f)", thr)
        except Exception as e:
            log.error("Failed to load EMBER model: %s", e)
    else:
        log.warning("EMBER model not found at %s", MODEL_PATH)

    return members


def _get_models() -> List[Tuple[Any, float, float]]:
    global _models, _model_loaded, _model_threshold
    if _model_loaded:
        return _models
    with _model_lock:
        if _model_loaded:
            return _models
        _models = _load_models_once()
        if _models:
            # Use primary model threshold as global reference
            _model_threshold = _models[0][2]
        _model_loaded = True
    return _models


# ── Feature extraction helpers (called inside ProcessPool workers) ─────────────

def _extract_and_score_worker(
    fp: str, cpp_score: int
) -> Tuple[str, Optional[int], List[str], Optional[dict]]:
    """
    Top‑level function (picklable) for ProcessPool.
    Executes LIEF extraction and EMBER LightGBM inference.
    """
    global _worker_models
    if _worker_models is None:
        _worker_models = _load_models_once()

    models = _worker_models
    if not models:
        return fp, None, ["AI model not trained — run train.bat"], None

    try:
        # 1. EMBER Extraction requires reading the raw binary
        with open(fp, "rb") as f:
            file_data = f.read()
            
        extractor = PEFeatureExtractor(2)
        vec = np.array(extractor.feature_vector(file_data), dtype=np.float32).reshape(1, -1)
        
    except Exception as e:
        return fp, None, [f"EMBER LIEF extraction error: {e}"], None

    # 2. LightGBM Inference
    mdl, w, thr = models[0]
    try:
        # LightGBM returns a direct array of probabilities, unlike sklearn's predict_proba
        prob = float(mdl.predict(vec)[0])
    except Exception as e:
        return fp, None, [f"EMBER inference error: {e}"], None

    # 3. Score mapping
    if prob >= thr:
        s = int(prob * 100)
    else:
        s = int(prob * 100 * AI_BELOW_THRESHOLD_WEIGHT)

    # 4. Generate Indicators
    inds = []
    if s >= (thr * 100):
        inds.append(f"High structural threat detected by EMBER (Conf: {s}%)")

    # Pass an empty dict so your _combine and _compute_hard_floor functions don't break
    dummy_feats = {"max_section_entropy": 0, "is_signed": False} 

    return fp, s, inds, dummy_feats


def _build_indicators(feats: dict, score: int, threshold: float) -> List[str]:
    """Generate human‑readable indicator strings from feature dict."""
    entropy      = feats.get("max_section_entropy", 0)
    is_dotnet    = feats.get("is_dotnet",    False)
    is_installer = feats.get("is_installer", False)
    is_signed    = feats.get("is_signed",    False)
    has_inj      = feats.get("has_process_injection_imports", False)
    has_net      = feats.get("has_network_imports",           False)
    has_crypto   = feats.get("has_crypto_imports",            False)
    has_priv     = feats.get("has_privilege_escalation",      False)
    has_keylog   = feats.get("has_keylogger_apis",            False)
    has_debug    = feats.get("has_anti_debug",                False)

    inds: List[str] = []
    if entropy > 7.2 and not is_dotnet and not is_installer:
        inds.append("High entropy — packed/encrypted")
    if has_inj:
        inds.append("Process injection APIs detected")
    if has_net and not is_signed:
        inds.append("Network APIs — possible C2")
    if has_crypto and has_net and not is_signed:
        inds.append("Crypto + network — possible encrypted C2")
    if has_crypto and has_debug and not is_signed:
        inds.append("Crypto + anti‑debug — packer evasion pattern")
    if has_priv:
        inds.append("Privilege escalation APIs detected")
    if has_keylog:
        inds.append("Keylogger APIs detected")
    if has_debug:
        inds.append("Anti‑debug / evasion techniques detected")
    if feats.get("section_count", 0) > 10:
        inds.append("Abnormal PE section count")
    if feats.get("has_invalid_imports"):
        inds.append("Invalid/obfuscated imports")
    if is_signed:
        inds.append("ℹ Digitally signed")
    return inds


# ── Batch AI engine ────────────────────────────────────────────────────────────

class _BatchQueue:
    """
    Accumulate (fp, cpp_score) pairs and flush them as a numpy batch.
    Delivers results back to callers via per‑file Future objects.
    """

    def __init__(self, pool: ProcessPoolExecutor) -> None:
        self._pool    = pool
        self._items:   List[Tuple[str, int, Future]] = []
        self._lock     = threading.Lock()
        self._flush_ev = threading.Event()
        self._flusher  = threading.Thread(
            target=self._flush_loop, daemon=True, name="BatchFlusher"
        )
        self._flusher.start()

    def submit(self, fp: str, cpp_score: int) -> Future:
        """Enqueue a file for batch inference. Returns a Future."""
        fut: Future = Future()
        with self._lock:
            self._items.append((fp, cpp_score, fut))
            if len(self._items) >= BATCH_SIZE:
                self._flush_ev.set()
        return fut

    def _flush_loop(self) -> None:
        while True:
            triggered = self._flush_ev.wait(timeout=BATCH_FLUSH_MS)
            self._flush_ev.clear()
            self._drain()

    def _drain(self) -> None:
        with self._lock:
            if not self._items:
                return
            batch = self._items[:]
            self._items.clear()

        if not batch:
            return

        metrics.inc("batch_flushes")
        # Submit each file to ProcessPool; results delivered to individual futures
        pool_futs = {
            self._pool.submit(_extract_and_score_worker, fp, cs): (fp, fut)
            for fp, cs, fut in batch
        }
        for pf in as_completed(pool_futs):
            fp_key, caller_fut = pool_futs[pf]
            try:
                result = pf.result(timeout=AI_TIMEOUT)
                caller_fut.set_result(result)
            except Exception as e:
                caller_fut.set_result((fp_key, None, [f"AI error: {e}"], None))

    def flush_sync(self) -> None:
        """Force immediate drain (used during shutdown / single‑file paths)."""
        self._flush_ev.set()


# Module‑level process pool and batch queue (initialised once)
_feature_pool:  Optional[ProcessPoolExecutor] = None
_batch_queue:   Optional[_BatchQueue]         = None
_pool_init_lock = threading.Lock()


def _get_pool_and_queue() -> Tuple[ProcessPoolExecutor, _BatchQueue]:
    global _feature_pool, _batch_queue
    if _feature_pool is not None:
        return _feature_pool, _batch_queue  # type: ignore[return-value]
    with _pool_init_lock:
        if _feature_pool is not None:
            return _feature_pool, _batch_queue  # type: ignore[return-value]
        _feature_pool = ProcessPoolExecutor(
            max_workers=FEATURE_WORKERS,
            initializer=_worker_init,
        )
        _batch_queue = _BatchQueue(_feature_pool)
        log.info("ProcessPoolExecutor started (workers=%d)", FEATURE_WORKERS)
    return _feature_pool, _batch_queue  # type: ignore[return-value]


def _worker_init() -> None:
    """Called once in each worker process. Pre‑loads models to avoid cold starts."""
    global _worker_models
    
    # 🚨 FIX 1: Gag the Python loggers (EMBER)
    import logging
    logging.getLogger("ember").setLevel(logging.ERROR)
    logging.getLogger("ember.features").setLevel(logging.ERROR)
    
    # 🚨 FIX 2: Gag the C++ loggers (LIEF) - Stops "Failed to parse DOS Stub"
    try:
        import lief
        lief.logging.disable()
    except ImportError:
        pass
    
    _worker_models = _load_models_once()
    log.debug("Worker PID %d: models pre‑loaded", os.getpid())


def _ai_single(fp: str, cpp_score: int = 0) -> Tuple[Optional[int], List[str], Optional[dict]]:
    """
    Single‑file AI path: submit to ProcessPool directly (no queue delay).
    Used by scan_file() for interactive / on‑demand scans.
    """
    pool, _ = _get_pool_and_queue()
    try:
        _, s, inds, feats = pool.submit(
            _extract_and_score_worker, fp, cpp_score
        ).result(timeout=AI_TIMEOUT)
        return s, inds, feats
    except Exception as e:
        metrics.inc("ai_errors")
        return None, [f"AI error: {e}"], None


# ── Scan‑future coalescing ─────────────────────────────────────────────────────
_inflight: Dict[str, Future] = {}
_inflight_lock = threading.Lock()


def _coalesced_scan(fp: str) -> Tuple[Optional[Future], bool]:
    """
    Return (existing_future, is_new).
    If is_new=True the caller must run the scan and call _release_inflight().
    If is_new=False the caller should await existing_future.
    """
    with _inflight_lock:
        existing = _inflight.get(fp)
        if existing is not None:
            return existing, False
        fut: Future = Future()
        _inflight[fp] = fut
        return fut, True


def _release_inflight(fp: str, fut: Future, result: dict) -> None:
    with _inflight_lock:
        _inflight.pop(fp, None)
    if not fut.done():
        fut.set_result(result)


# ── Hard floor logic ───────────────────────────────────────────────────────────

def _compute_hard_floor(feats: Optional[dict], fp: str) -> Tuple[int, str]:
    if feats is None:
        return 0, ""

    entropy      = feats.get("max_section_entropy", 0)
    is_dotnet    = feats.get("is_dotnet",    False)
    is_installer = feats.get("is_installer", False)
    is_signed    = feats.get("is_signed",    False)
    has_inj      = feats.get("has_process_injection_imports", False)
    has_net      = feats.get("has_network_imports",           False)
    has_crypto   = feats.get("has_crypto_imports",            False)
    has_priv     = feats.get("has_privilege_escalation",      False)
    has_keylog   = feats.get("has_keylogger_apis",            False)
    has_debug    = feats.get("has_anti_debug",                False)

    if entropy >= HARD_FLOOR_ENTROPY and not is_dotnet and not is_installer:
        return HARD_FLOOR_SCORE, f"Entropy {entropy:.2f} ≥ {HARD_FLOOR_ENTROPY} hard‑floor"
    if has_inj and has_net:
        return HIGH_RISK_FEATURE_FLOOR, "Process injection + network APIs (RAT/loader)"
    if has_priv and has_net:
        return HIGH_RISK_FEATURE_FLOOR, "Privilege escalation + network APIs"
    if has_keylog:
        return HIGH_RISK_FEATURE_FLOOR, "Keylogger APIs detected"
    if has_crypto and has_debug and not is_signed:
        return HARD_FLOOR_SCORE, "Crypto + anti‑debug (packer evasion)"
    if not is_signed and has_net:
        return MIN_SCORE_UNSIGNED_NETWORK, "Unsigned binary with network communication APIs"
    return 0, ""


def _strong_indicator_count(feats: Optional[dict]) -> int:
    if feats is None:
        return 0
    indicators = [
        "has_process_injection_imports", "has_network_imports",
        "has_privilege_escalation", "has_keylogger_apis", "has_anti_debug",
        "has_crypto_imports", "has_invalid_imports",
    ]
    count = sum(1 for k in indicators if feats.get(k))
    if feats.get("max_section_entropy", 0) > 7.0:
        count += 1
    return count


# ── Trust helpers ──────────────────────────────────────────────────────────────

def _trusted_path(fp: str) -> bool:
    norm = fp.lower().replace("/", "\\")
    return any(norm.startswith(p) for p in TRUSTED_PREFIXES)


def _is_trusted_publisher(pub: str) -> bool:
    if not pub:
        return False
    if pub in TRUSTED_PUBLISHERS:
        return True
    pub_low = pub.lower()
    return any(kw in pub_low for kw in TRUSTED_PUBLISHER_KEYWORDS)


def _has_trust_signals(feats: dict, fp: str) -> Tuple[bool, str]:
    reasons: List[str] = []
    if feats.get("is_signed"):                              reasons.append("digitally signed")
    if feats.get("is_dotnet"):                              reasons.append(".NET assembly")
    if feats.get("is_system_path") or _trusted_path(fp):   reasons.append("system path")
    return bool(reasons), ", ".join(reasons)


# ── Score combination ──────────────────────────────────────────────────────────
# ── Score combination ──────────────────────────────────────────────────────────
def _combine(
    cpp:   Optional[int],
    ai:    Optional[int],
    fp:    str,
    feats: Optional[dict] = None,
) -> Tuple[int, str, str]:
    fp_lower = fp.lower()

    if fp_lower.endswith("heuristicscanner.exe"):
        return 0, "whitelisted", "Scanner executable ignored"

    h = _file_hash(fp)
    if _in_whitelist(h):
        return 0, "whitelisted_hash", "File hash in global whitelist"

    # 1. Pessimistic Merging (Take the highest threat level)
    if cpp is not None and ai is not None:
        weighted = int(cpp * CPP_W + ai * AI_W)
        base = max(cpp, ai, weighted)
        method = "pessimistic_merge"
    elif cpp is not None:
        base, method = cpp, "cpp_only"
    elif ai is not None:
        base, method = ai, "ai_only"
    else:
        return 0, "no_data", ""

    veto_reason = ""
    final_score = base

    # 2. Apply Hard Floors (Zero False-Negative overrides)
    floor_val, floor_rsn = _compute_hard_floor(feats, fp)
    if floor_val > final_score:
        final_score = floor_val
        method = "hard_floor"
        veto_reason = floor_rsn

    # 3. Apply Trust Caps (Prevents flagging core OS files)
    if feats:
        is_trusted, trust_rsn = _has_trust_signals(feats, fp)
        strong_inds = _strong_indicator_count(feats)
        
        if is_trusted and strong_inds < BYPASS_TRUST_MIN_INDICATORS:
            if feats.get("is_signed") and final_score > TRUSTED_PUB_SCORE_CAP:
                final_score = TRUSTED_PUB_SCORE_CAP
                method = "trust_cap"
                veto_reason = "Score capped due to trusted publisher"
            elif final_score > TRUSTED_PATH_SCORE_CAP:
                final_score = TRUSTED_PATH_SCORE_CAP
                method = "trust_cap"
                veto_reason = "Score capped due to trusted system path"

    # THIS IS THE CRITICAL LINE THAT WAS MISSING!
    return final_score, method, veto_reason


# ── File hashing ───────────────────────────────────────────────────────────────

def _file_hash(filepath: str) -> str:
    cached = _hash_lru.get(filepath)
    if cached:
        return cached

    sha = hashlib.sha256()
    try:
        size = os.path.getsize(filepath)
        if size == 0:
            h = sha.hexdigest()
        elif size > 16 * 1024 * 1024:
            with open(filepath, "rb") as fh:
                with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    sha.update(mm)
            h = sha.hexdigest()
        else:
            with open(filepath, "rb") as fh:
                for chunk in iter(lambda: fh.read(131_072), b""):
                    sha.update(chunk)
            h = sha.hexdigest()
    except Exception:
        return ""

    _hash_lru.set(filepath, h)
    return h


def _safe_resolve(raw_path: str, allowed_base: Optional[str] = None) -> Optional[str]:
    if "\x00" in raw_path:
        return None
    try:
        resolved = Path(raw_path).resolve()
    except Exception:
        return None
    if allowed_base is not None:
        try:
            resolved.relative_to(Path(allowed_base).resolve())
        except ValueError:
            return None
    return str(resolved)


# ── Priority classification ────────────────────────────────────────────────────

def _is_high_priority(fp: str) -> bool:
    """True for files in risky locations — yielded first in folder scans."""
    fp_low = fp.lower()
    return any(p.search(fp_low) for p in _PRIORITY_PATTERNS)


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    file:           str
    filename:       str
    cpp_score:      Optional[int]
    ai_score:       Optional[int]
    final_score:    Optional[int]
    verdict:        str
    method:         str
    indicators:     list = field(default_factory=list)
    error:          bool = False
    progress:       dict = field(default_factory=dict)
    file_size:      int  = 0
    veto_reason:    str  = ""
    scan_id:        str  = field(default_factory=lambda: str(uuid.uuid4()))
    scan_time_ms:   int  = 0
    from_cache:     bool = False
    bridge_version: str  = __version__
    metadata:       dict = field(default_factory=dict) # 🚨 NEW: Holds VT-style data

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict_class"] = self.verdict.lower().replace(" ", "_")
        return d


def _verdict(score: int) -> str:
    if score >= 80: return "HIGH RISK"
    if score >= 50: return "SUSPICIOUS"
    if score >= 20: return "LOW RISK"
    return "CLEAN"


# ── Result builder ─────────────────────────────────────────────────────────────

def _dedup_indicators(raw: List[dict]) -> List[dict]:
    """Remove duplicate indicator text while preserving source attribution."""
    seen: Set[str] = set()
    out:  List[dict] = []
    for item in raw:
        key = item.get("text", "").strip().lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _build(
    fp:        str,
    cs:        Optional[int],
    ci:        List[str],
    ai_result: Tuple,
    prog:      Optional[dict] = None,
    t_start:   Optional[float] = None,
    meta:      Optional[dict] = None,
) -> dict:
    ai_s   = ai_result[1] if len(ai_result) > 1 else None
    ai_i   = ai_result[2] if len(ai_result) > 2 else []
    feats  = ai_result[3] if len(ai_result) > 3 else None

    final, method, veto_reason = _combine(cs, ai_s, fp, feats)
    verdict = _verdict(final)

    metrics.inc("scans_total")
    _metric_map = {
        "CLEAN":      "scans_clean",
        "SUSPICIOUS": "scans_suspicious",
        "HIGH RISK":  "scans_high_risk",
    }
    if verdict in _metric_map:
        metrics.inc(_metric_map[verdict])

    raw_inds = (
        [{"source": "C++", "text": t} for t in (ci   or [])] +
        [{"source": "AI",  "text": t} for t in (ai_i or [])]
    )
    indicators = _dedup_indicators(raw_inds)
    if veto_reason:
        indicators.insert(0, {"source": "Bridge", "text": f"⚠ {veto_reason}"})

    try:
        sz = os.path.getsize(fp) if os.path.exists(fp) else 0
    except OSError:
        sz = 0

    elapsed_ms = int((time.monotonic() - t_start) * 1000) if t_start else 0

    return ScanResult(
        file=fp, filename=os.path.basename(fp),
        cpp_score=cs, ai_score=ai_s, final_score=final,
        verdict=verdict, method=method,
        indicators=indicators, file_size=sz,
        progress=prog or {}, veto_reason=veto_reason,
        scan_time_ms=elapsed_ms,
        metadata=meta or {},
    ).to_dict()


def _error_result(fp: str, msg: str, source: str) -> dict:
    metrics.inc("scans_error")
    return ScanResult(
        file=fp, filename=os.path.basename(fp),
        cpp_score=None, ai_score=None, final_score=None,
        verdict="ERROR", method="error", error=True,
        indicators=[{"source": source, "text": msg}],
    ).to_dict()


# ── Cache helpers ──────────────────────────────────────────────────────────────

def _cache_key(fp: str) -> Optional[str]:
    try:
        return f"{fp}|{os.path.getmtime(fp)}"
    except OSError:
        return fp


def _lookup_cache(key: str) -> Optional[dict]:
    # 1. Check local LRU first (zero network overhead)
    local = _result_cache.get(key)
    if local is not None:
        metrics.inc("cache_hits")
        return {**local, "from_cache": True}
    # 2. Check Redis (shared across nodes)
    remote = _redis_get(key)
    if remote is not None:
        _result_cache.set(key, remote)      # Warm local cache
        return {**remote, "from_cache": True}
    metrics.inc("cache_misses")
    return None


def _store_cache(key: str, result: dict) -> None:
    _result_cache.set(key, result)
    _redis_set(key, result)


def _get_extended_metadata(fp: str) -> dict:
    """
    Tier-1 Enterprise Static Analysis Metadata Extractor.
    Extracts Hashes, Network IoCs, Imphash, Section Entropies, and MITRE capabilities.
    """
    meta = {}
    try:
        # ==========================================
        # 1. BASIC PROPERTIES & MAGIC
        # ==========================================
        sz = os.path.getsize(fp)
        meta["File Size"] = f"{sz / 1024:.2f} KB ({sz} bytes)"
        meta["Extension"] = os.path.splitext(fp)[1].upper() or "UNKNOWN"

        # ==========================================
        # 2. CRYPTOGRAPHIC HASHES (VirusTotal Standard)
        # ==========================================
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        with open(fp, "rb") as f:
            for chunk in iter(lambda: f.read(131_072), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        meta["MD5"] = md5.hexdigest()
        meta["SHA-1"] = sha1.hexdigest()
        meta["SHA-256"] = sha256.hexdigest()

        # ==========================================
        # 3. NETWORK INDICATORS (Raw String Extraction)
        # ==========================================
        try:
            with open(fp, "rb") as f:
                raw_bytes = f.read(2 * 1024 * 1024) # Read first 2MB for speed
                
                # Extract URLs
                urls = re.findall(b'https?://[a-zA-Z0-9./_-]+', raw_bytes)
                unique_urls = list(set([u.decode('utf-8', errors='ignore') for u in urls]))
                if unique_urls:
                    meta["Extracted URLs"] = ", ".join(unique_urls[:5]) + ("..." if len(unique_urls) > 5 else "")
                    
                # Extract IPs (Basic IPv4 format)
                ips = re.findall(b'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b', raw_bytes)
                # Filter out common false positives (like version numbers)
                unique_ips = [ip.decode('utf-8') for ip in set(ips) if not ip.startswith(b'0.') and not ip.startswith(b'255.')]
                if unique_ips:
                    meta["Extracted IPs"] = ", ".join(unique_ips[:5])
        except Exception:
            pass

        # ==========================================
        # 4. DEEP PE REVERSE ENGINEERING (Windows EXEs/DLLs)
        # ==========================================
        if pefile is not None:
            try:
                pe = pefile.PE(fp, fast_load=False)
                
                # -- Headers & Architecture --
                machine_type = pe.FILE_HEADER.Machine
                meta["Architecture"] = "x64 (64-bit)" if machine_type == 0x8664 else "x86 (32-bit)" if machine_type == 0x014c else hex(machine_type)
                
                subsystem_map = {1: "Native / Driver", 2: "Windows GUI (Hidden/App)", 3: "Windows Console (Terminal)"}
                meta["Subsystem"] = subsystem_map.get(pe.OPTIONAL_HEADER.Subsystem, f"Unknown ({pe.OPTIONAL_HEADER.Subsystem})")
                
                timestamp = pe.FILE_HEADER.TimeDateStamp
                meta["Compilation Time"] = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')

                # -- Imphash (Industry Standard Threat Tracking) --
                meta["Imphash"] = pe.get_imphash()

                # -- Digital Signature Check --
                security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
                meta["Digital Signature"] = "Present (Authenticode attached)" if security_dir.VirtualAddress > 0 else "Missing / Unsigned"

                # -- Sections & Packer Detection --
                sections = []
                is_packed = False
                for section in pe.sections:
                    name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    entropy = section.get_entropy()
                    
                    # Entropy > 7.2 usually indicates compressed, packed, or encrypted data
                    if entropy > 7.2:
                        is_packed = True
                        name = f"⚠️ {name}"
                    sections.append(f"{name} ({entropy:.2f})")
                
                meta["Memory Sections (Entropy)"] = " | ".join(sections)
                if is_packed:
                    meta["Packer Warning"] = "High entropy detected! File is likely packed or encrypted."

                # -- MITRE ATT&CK Capability Mapping (API Analysis) --
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    imported_apis = []
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                imported_apis.append(imp.name.decode('utf-8', errors='ignore'))
                    
                    # Map suspicious APIs to MITRE Tactics
                    capabilities = []
                    api_str = " ".join(imported_apis).lower()
                    
                    if any(api in api_str for api in ['virtualalloc', 'createremotethread', 'writeprocessmemory']):
                        capabilities.append("[T1055] Process Injection")
                    if any(api in api_str for api in ['setwindowshookex', 'getasynckeystate']):
                        capabilities.append("[T1056] Keylogging / Input Capture")
                    if any(api in api_str for api in ['cryptacquirecontext', 'cryptencrypt']):
                        capabilities.append("[T1486] Data Encrypted (Ransomware Capability)")
                    if any(api in api_str for api in ['internetopen', 'winhttprequest']):
                        capabilities.append("[T1071] Application Layer Protocol (C2 Comm)")
                    if any(api in api_str for api in ['regcreatekey', 'regsetvalue']):
                        capabilities.append("[T1112] Registry Modification")

                    if capabilities:
                        meta["Suspicious Capabilities"] = ", ".join(capabilities)
                    
                    # Add top DLLs for context
                    dlls = [entry.dll.decode('utf-8', errors='ignore').lower() for entry in pe.DIRECTORY_ENTRY_IMPORT]
                    meta["Imported Libraries"] = ", ".join(dlls[:8])

            except Exception as e:
                # Silently skip PE parsing if the file is an APK, PDF, or broken binary
                pass

    except Exception:
        pass
    
    return meta


def scan_file(filepath: str, allowed_base: Optional[str] = None) -> dict:
    """Single file scan: C++ and AI run concurrently."""
    fp = _safe_resolve(filepath, allowed_base)
    if fp is None:
        return _error_result(str(filepath).replace("\x00", "[NULL]"), "Invalid path", "Security")
    if not os.path.isfile(fp):
        return _error_result(fp, "File not found", "System")

    ck = _cache_key(fp)
    if ck:
        cached = _lookup_cache(ck)
        if cached is not None:
            return cached

    coalesced_fut, is_new = _coalesced_scan(fp)
    if not is_new:
        metrics.inc("coalesced_hits")
        try:
            return coalesced_fut.result(timeout=CPP_TIMEOUT + AI_TIMEOUT + 10)
        except Exception:
            return _error_result(fp, "Coalesced scan failed", "System")

    acquired = _scan_semaphore.acquire(timeout=60)
    if not acquired:
        err = _error_result(fp, "Server busy — too many concurrent scans", "System")
        _release_inflight(fp, coalesced_fut, err)
        return err

    t_start = time.monotonic()
    try:
        # 🚨 NEW: Grab the heavy metadata
        file_meta = _get_extended_metadata(fp) 

        cs, ci = _cpp_file(fp)
        c_score = cs or 0

        if c_score >= 90 or (c_score == 0 and _in_whitelist(_file_hash(fp))):
            result = _build(fp, cs, ci or [], (fp, None, []), t_start=t_start, meta=file_meta)
        else:
            ai_res = _ai_single(fp, cpp_score=c_score)
            result = _build(fp, cs, ci or [], (fp, ai_res[0], ai_res[1], ai_res[2]), t_start=t_start, meta=file_meta)

        if ck:
            _store_cache(ck, result)
        _release_inflight(fp, coalesced_fut, result)
        return result

    # 🚨 THE MISSING BLOCKS: Handle errors and release the concurrency lock!
    except Exception as e:
        log.exception("scan_file error for %s", fp)
        err = _error_result(fp, f"Unexpected error: {e}", "System")
        _release_inflight(fp, coalesced_fut, err)
        return err
    finally:
        _scan_semaphore.release()

def scan_folder(dirpath: str, allowed_base: Optional[str] = None) -> Iterator[dict]:
    """
    True Single-Pass Streaming Folder Scanner.
    Uses Python's robust directory walker to bypass locked OS folders safely,
    then feeds files into the C++ IPC Server for lightning-fast analysis.
    """
    dp = _safe_resolve(dirpath, allowed_base)
    if dp is None or not os.path.isdir(dp):
        return

    log.info("Starting ultra-fast streaming folder scan: %s", dp)
    _, bq = _get_pool_and_queue()

    idx = 0
    ai_futures: Dict[Future, Tuple[str, Optional[int], List[str], int]] = {}

    # 1. Robust Python directory walker (safely ignores Permission Denied errors)
    def fast_walk(target_dir):
        try:
            for root_dir, _, files in os.walk(target_dir, onerror=lambda e: None):
                for f in files:
                    try:
                        if os.path.splitext(f)[1].lower() in SCAN_EXTS:
                            yield os.path.join(root_dir, f)
                    except Exception:
                        pass
        except Exception:
            pass

    for fp in fast_walk(dp):
        idx += 1

        # 2. Check Cache
        ck = _cache_key(fp)
        if ck:
            cached = _lookup_cache(ck)
            if cached is not None:
                cached["progress"] = {"current": idx, "total": 0, "percent": 0}
                yield cached
                continue

        # 3. Ask C++ Engine via IPC
        cs, ci = _cpp_file(fp)
        c_score = cs or 0
        is_cpp_trusted = any("Trusted" in str(ind) for ind in (ci or []))

        # 4. The Bulletproof Threat Funnel
        if c_score >= 90 or (c_score == 0 and (is_cpp_trusted or _in_whitelist(_file_hash(fp)))):
            result = _build(
                fp, cs, ci, (fp, None, []),
                prog={"current": idx, "total": 0, "percent": 0}
            )
            if ck:
                _store_cache(ck, result)
            yield result
        else:
            # Ambiguous file - send to AI Queue
            fut = bq.submit(fp, c_score)
            ai_futures[fut] = (fp, cs, ci, idx)

        # 5. Yield finished AI jobs immediately
        done_futs = [f for f in ai_futures if f.done()]
        for f in done_futs:
            afp, acs, aci, aidx = ai_futures.pop(f)
            try:
                _, ai_s, ai_i, feats = f.result()
                res = _build(afp, acs, aci, (afp, ai_s, ai_i, feats), prog={"current": aidx, "total": 0, "percent": 0})
            except Exception as e:
                res = _error_result(afp, f"AI error: {e}", "AI")
                res["progress"] = {"current": aidx, "total": 0, "percent": 0}

            if _cache_key(afp):
                _store_cache(_cache_key(afp), res)
            yield res

    # 6. Drain remaining AI jobs
    for fut in as_completed(ai_futures.keys()):
        afp, acs, aci, aidx = ai_futures[fut]
        try:
            _, ai_s, ai_i, feats = fut.result(timeout=AI_TIMEOUT)
            res = _build(afp, acs, aci, (afp, ai_s, ai_i, feats), prog={"current": aidx, "total": idx, "percent": 100})
        except Exception as e:
            res = _error_result(afp, f"AI error: {e}", "AI")
            res["progress"] = {"current": aidx, "total": idx, "percent": 100}

        if _cache_key(afp):
            _store_cache(_cache_key(afp), res)
        yield res

    log.info("Folder scan complete: %d files processed", idx)

def _walk_exes(root: str) -> Iterator[str]:
    """Fallback generator for when C++ scanner is unavailable."""
    try:
        for dirpath, _, filenames in os.walk(root):
            for f in filenames:
                if Path(f).suffix.lower() in SCAN_EXTS:
                    yield os.path.join(dirpath, f)
    except PermissionError:
        pass


# ── Graceful shutdown ──────────────────────────────────────────────────────────

def _shutdown(signum=None, frame=None) -> None:
    log.info("Graceful shutdown: draining in‑flight scans…")
    _ipc_scanner.close()
    if _feature_pool:
        _feature_pool.shutdown(wait=True)
    log.info("Bridge shut down cleanly.")


signal.signal(signal.SIGTERM, _shutdown)


# ── Operational APIs ───────────────────────────────────────────────────────────

def get_metrics() -> Dict[str, Any]:
    snap = metrics.snapshot()
    snap["cpp_circuit_state"] = _cpp_cb.state
    snap["ipc_scanner_alive"] = _ipc_scanner._alive
    snap["model_count"]       = len(_get_models())
    snap["model_threshold"]   = _model_threshold
    snap["whitelist_size"]    = len(_get_whitelist()[0])
    snap["feature_workers"]   = FEATURE_WORKERS
    snap["ai_workers"]        = AI_WORKERS
    snap["max_concurrent"]    = MAX_CONCURRENT
    snap["bridge_version"]    = __version__
    snap["redis_enabled"]     = bool(REDIS_URL)
    return snap


def reload_whitelist() -> int:
    global _whitelist_hashes, _whitelist_bloom
    with _whitelist_lock:
        _whitelist_hashes = None
        _whitelist_bloom  = None
    count = len(_get_whitelist()[0])
    log.info("Whitelist reloaded: %d hashes", count)
    return count


def reload_model() -> bool:
    global _models, _model_threshold, _model_loaded, _worker_models
    with _model_lock:
        _models       = []
        _model_loaded = False
        _worker_models = None
    ok = bool(_get_models())
    log.info("Model reloaded: %s", "OK" if ok else "FAILED")
    return ok


# ── Module warm‑up ─────────────────────────────────────────────────────────────
def _warm_up() -> None:
    try:
        _get_models()
        _get_pool_and_queue()
        _get_whitelist()
        log.info(
            "Bridge v%s ready — %d model(s), %d whitelist hashes, "
            "pool workers=%d, Redis=%s",
            __version__,
            len(_models),
            len(_whitelist_hashes or []),
            FEATURE_WORKERS,
            "on" if REDIS_URL else "off",
        )
    except Exception as e:
        log.warning("Warm‑up error (non‑fatal): %s", e)


_warm_up()
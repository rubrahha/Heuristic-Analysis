"""
╔══════════════════════════════════════════════════════════════════════════════╗
║             HeuristicScanner AI  —  Dataset Setup  (v2.0)                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  USAGE                                                                       ║
║    python dataset_setup.py                  — collect + status              ║
║    python dataset_setup.py --status         — status only                   ║
║    python dataset_setup.py --split          — (re)build train/test split    ║
║    python dataset_setup.py --clean-target N — collect N clean samples       ║
║    python dataset_setup.py --workers N      — parallel workers (default 8)  ║
║    python dataset_setup.py --rebuild-index  — force rebuild dataset index   ║
║                                                                              ║
║  DROP FILES INTO                                                             ║
║    ai/dataset/malware/    ← .exe .dll .scr .sys .ocx  (or ZIPs)            ║
║    ai/dataset/clean/      ← trusted PE files  (or ZIPs)                    ║
║                                                                              ║
║  PIPELINE                                                                    ║
║    collect → deduplicate → index → split → train.bat                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import shutil
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION  (edit here — no need to touch the code below)
# ══════════════════════════════════════════════════════════════════════════════

class Config:
    # Paths
    BASE         = Path(__file__).parent
    DATASET_DIR  = BASE / "dataset"
    MALWARE_DIR  = DATASET_DIR / "malware"
    CLEAN_DIR    = DATASET_DIR / "clean"
    TRAIN_DIR    = DATASET_DIR / "train"
    TEST_DIR     = DATASET_DIR / "test"
    LOG_DIR      = BASE / "logs"
    MODEL_DIR    = BASE / "models"
    INDEX_FILE   = DATASET_DIR / "dataset_index.json"
    HASH_CACHE   = DATASET_DIR / ".hash_cache.json"

    # Dataset parameters
    CLEAN_TARGET   : int   = 2000
    TRAIN_RATIO    : float = 0.80      # 80% train / 20% test
    MIN_FILE_BYTES : int   = 8_000
    MAX_FILE_BYTES : int   = 100_000_000
    BALANCE_WARN   : float = 0.60      # warn if min/max ratio drops below this
    BATCH_SIZE     : int   = 256

    # Performance
    WORKERS : int = 8

    # Supported PE extensions
    PE_EXTS = frozenset({".exe", ".dll", ".scr", ".sys", ".ocx"})

    # Malware ZIP passwords to try (in order)
    ZIP_PASSWORDS = [b"infected", b"malware", b"virus", b"password", b""]


# ══════════════════════════════════════════════════════════════════════════════
#  TERMINAL COLOURS  (no third-party libs required)
# ══════════════════════════════════════════════════════════════════════════════

class C:
    """ANSI colour helpers — degrade silently on Windows without VT mode."""
    _ON = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

    @staticmethod
    def _w(code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if C._ON else text

    green  = staticmethod(lambda t: C._w("32",    t))
    yellow = staticmethod(lambda t: C._w("33",    t))
    red    = staticmethod(lambda t: C._w("31",    t))
    cyan   = staticmethod(lambda t: C._w("36",    t))
    bold   = staticmethod(lambda t: C._w("1",     t))
    dim    = staticmethod(lambda t: C._w("2",     t))
    ok     = staticmethod(lambda t: C._w("32;1",  f"✓  {t}"))
    warn   = staticmethod(lambda t: C._w("33;1",  f"⚠  {t}"))
    err    = staticmethod(lambda t: C._w("31;1",  f"✗  {t}"))
    info   = staticmethod(lambda t: C._w("36",    f"   {t}"))


# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════════════════

def setup_logging() -> logging.Logger:
    Config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = Config.LOG_DIR / f"dataset_{datetime.now():%Y%m%d_%H%M%S}.log"

    fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                            datefmt="%H:%M:%S")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.DEBUG)

    logger = logging.getLogger("heuristic")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    return logger


log = setup_logging()


# ══════════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class FileRecord:
    filename : str
    sha256   : str
    label    : str          # "malware" | "clean"
    split    : str          # "train"   | "test"
    size     : int
    added_at : str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


# ══════════════════════════════════════════════════════════════════════════════
#  HASH UTILITIES  (with persistent on-disk cache)
# ══════════════════════════════════════════════════════════════════════════════

class HashCache:
    """
    Persistent path → sha256 mapping.
    Avoids recomputing hashes for files that haven't changed (uses mtime+size as
    cache key so stale entries are invalidated automatically).
    """

    def __init__(self, cache_path: Path):
        self._path  = cache_path
        # stored as  { abs_path: [mtime_ns, size, hex_digest] }
        self._store : dict[str, list] = {}
        self._dirty = False
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as fh:
                    self._store = json.load(fh)
            except Exception:
                self._store = {}

    def flush(self):
        if not self._dirty:
            return
        tmp = self._path.with_suffix(".tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._store, fh, separators=(",", ":"))
            tmp.replace(self._path)
            self._dirty = False
        except Exception as exc:
            log.warning("Could not save hash cache: %s", exc)

    def get(self, path: Path) -> Optional[str]:
        key = str(path)
        entry = self._store.get(key)
        if entry is None:
            return None
        mtime_ns, size, digest = entry
        try:
            st = path.stat()
            if st.st_mtime_ns == mtime_ns and st.st_size == size:
                return digest
        except OSError:
            pass
        return None

    def set(self, path: Path, digest: str):
        try:
            st = path.stat()
            self._store[str(path)] = [st.st_mtime_ns, st.st_size, digest]
            self._dirty = True
        except OSError:
            pass


_hash_cache: Optional[HashCache] = None


def get_hash_cache() -> HashCache:
    global _hash_cache
    if _hash_cache is None:
        _hash_cache = HashCache(Config.HASH_CACHE)
    return _hash_cache


def sha256_of(path: Path) -> str:
    """Return SHA-256 hex digest, using the persistent cache."""
    cache = get_hash_cache()
    cached = cache.get(path)
    if cached:
        return cached
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    digest = h.hexdigest()
    cache.set(path, digest)
    return digest


# ══════════════════════════════════════════════════════════════════════════════
#  FOLDER INIT
# ══════════════════════════════════════════════════════════════════════════════

def ensure_folders():
    for d in (Config.MALWARE_DIR, Config.CLEAN_DIR,
              Config.TRAIN_DIR / "malware", Config.TRAIN_DIR / "clean",
              Config.TEST_DIR  / "malware", Config.TEST_DIR  / "clean",
              Config.LOG_DIR,   Config.MODEL_DIR):
        d.mkdir(parents=True, exist_ok=True)


# ══════════════════════════════════════════════════════════════════════════════
#  PE FILE DISCOVERY
# ══════════════════════════════════════════════════════════════════════════════

def iter_pe(folder: Path) -> Iterator[Path]:
    """Yield valid PE files in *folder* (non-recursive, existing only)."""
    try:
        for f in folder.iterdir():
            if f.is_file() and f.suffix.lower() in Config.PE_EXTS:
                try:
                    sz = f.stat().st_size
                    if Config.MIN_FILE_BYTES <= sz <= Config.MAX_FILE_BYTES:
                        yield f
                except OSError:
                    pass
    except OSError:
        pass


def count_pe(folder: Path) -> int:
    return sum(1 for _ in iter_pe(folder))


# ══════════════════════════════════════════════════════════════════════════════
#  PROGRESS BAR  (no dependencies)
# ══════════════════════════════════════════════════════════════════════════════

class Progress:
    BAR_WIDTH = 32

    def __init__(self, total: int, prefix: str = ""):
        self.total   = max(total, 1)
        self.prefix  = prefix
        self._done   = 0
        self._start  = time.monotonic()
        self._last_t = 0.0

    def update(self, n: int = 1):
        self._done = min(self._done + n, self.total)
        now = time.monotonic()
        if now - self._last_t < 0.12 and self._done < self.total:
            return
        self._last_t = now
        self._render()

    def _render(self):
        pct     = self._done / self.total
        filled  = int(self.BAR_WIDTH * pct)
        bar     = "█" * filled + "░" * (self.BAR_WIDTH - filled)
        elapsed = time.monotonic() - self._start
        speed   = self._done / elapsed if elapsed > 0.001 else 0
        eta_s   = (self.total - self._done) / speed if speed > 0 else 0
        eta     = f"ETA {eta_s:.0f}s" if self._done < self.total else f"done in {elapsed:.1f}s"
        line    = (f"  {self.prefix}  [{C.cyan(bar)}]  "
                   f"{self._done:>6,}/{self.total:,}  "
                   f"{C.dim(f'{speed:.0f} f/s')}  {C.dim(eta)}")
        print(f"\r{line}   ", end="", flush=True)

    def finish(self):
        self._done = self.total
        self._render()
        print()


# ══════════════════════════════════════════════════════════════════════════════
#  ZIP EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def extract_zips(folder: Path) -> int:
    zips = list(folder.glob("*.zip"))
    if not zips:
        return 0

    print(C.info(f"Found {len(zips)} ZIP file(s) in {folder.name}/ — extracting..."))
    extracted = 0

    for zpath in zips:
        opened = False
        for pwd in Config.ZIP_PASSWORDS:
            try:
                with zipfile.ZipFile(zpath) as z:
                    opened = True
                    for name in z.namelist():
                        ext = Path(name).suffix.lower()
                        if ext not in Config.PE_EXTS:
                            continue
                        try:
                            data = z.read(name, pwd=pwd)
                            if len(data) < Config.MIN_FILE_BYTES:
                                continue
                            digest = hashlib.sha256(data).hexdigest()
                            out = folder / f"{Path(name).stem}_{digest[:8]}{ext}"
                            if not out.exists():
                                out.write_bytes(data)
                                extracted += 1
                                log.info("Extracted %s from %s", out.name, zpath.name)
                        except Exception:
                            pass
                break
            except zipfile.BadZipFile:
                break
            except Exception:
                continue

        if opened:
            try:
                zpath.unlink()
            except OSError:
                pass
        else:
            print(C.warn(f"Could not open {zpath.name} — skipping"))

    if extracted:
        print(C.ok(f"Extracted {extracted} PE file(s) from ZIPs"))
    return extracted


# ══════════════════════════════════════════════════════════════════════════════
#  PARALLEL HASHING HELPER
# ══════════════════════════════════════════════════════════════════════════════

def _hash_worker(path: Path) -> tuple[Path, str] | tuple[Path, None]:
    try:
        return path, sha256_of(path)
    except Exception as exc:
        log.warning("Hashing failed for %s: %s", path, exc)
        return path, None


def build_known_hashes(folder: Path, workers: int) -> set[str]:
    """Return set of sha256 digests for all PE files already in *folder*."""
    files = list(iter_pe(folder))
    if not files:
        return set()

    known: set[str] = set()
    prog = Progress(len(files), prefix=f"Indexing {folder.name}")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_hash_worker, f): f for f in files}
        for fut in as_completed(futs):
            _, digest = fut.result()
            if digest:
                known.add(digest)
            prog.update()

    prog.finish()
    get_hash_cache().flush()
    return known


# ══════════════════════════════════════════════════════════════════════════════
#  CLEAN SAMPLE COLLECTION
# ══════════════════════════════════════════════════════════════════════════════

def _windows_clean_sources() -> list[Path]:
    env = os.environ.get
    winroot  = Path(env("SystemRoot",        "C:/Windows"))
    pf64     = Path(env("ProgramFiles",      "C:/Program Files"))
    pf86     = Path(env("ProgramFiles(x86)", "C:/Program Files (x86)"))
    appdata  = Path(env("APPDATA",           ""))
    localapp = Path(env("LOCALAPPDATA",      ""))

    sources = [
        winroot / "System32",
        winroot / "SysWOW64",
        winroot / "Microsoft.NET",
        pf64,
        pf86,
        pf64 / "dotnet",
        pf64 / "Git" / "usr" / "bin",
        pf64 / "nodejs",
        pf64 / "Windows Defender",
        pf86 / "Windows Defender",
    ]

    for sub in ["Spotify", "Telegram Desktop", "discord", "Microsoft/Teams"]:
        sources.append(appdata / sub)

    for sub in ["Discord", "Programs", "Google/Chrome/Application",
                "Microsoft/Edge/Application"]:
        sources.append(localapp / sub)

    for p in [pf64 / "Steam", pf86 / "Steam", pf64 / "Epic Games",
              Path("C:/Games"), Path("D:/Games"), Path("D:/SteamLibrary")]:
        sources.append(p)

    return [s for s in sources if s.exists()]


def _scan_candidates(sources: list[Path], workers: int) -> list[Path]:
    """Recursively discover candidate PE files across all sources in parallel."""
    candidates: list[Path] = []

    def _scan_one(src: Path) -> list[Path]:
        found = []
        try:
            for f in src.rglob("*"):
                if f.is_file() and f.suffix.lower() in Config.PE_EXTS:
                    try:
                        sz = f.stat().st_size
                        if Config.MIN_FILE_BYTES <= sz <= Config.MAX_FILE_BYTES:
                            found.append(f)
                    except OSError:
                        pass
        except OSError:
            pass
        return found

    print(C.info(f"Scanning {len(sources)} source directories..."))
    with ThreadPoolExecutor(max_workers=min(workers, len(sources))) as pool:
        for batch in as_completed({pool.submit(_scan_one, s): s for s in sources}):
            candidates.extend(batch.result())

    random.shuffle(candidates)
    return candidates


def collect_clean(target: int = Config.CLEAN_TARGET, workers: int = Config.WORKERS):
    existing = count_pe(Config.CLEAN_DIR)
    if existing >= target:
        print(C.ok(f"Clean samples: {existing:,}  (target {target:,} already reached)"))
        return

    need = target - existing
    print(C.info(f"Clean samples: {existing:,}  — need {need:,} more"))

    sources    = _windows_clean_sources()
    candidates = _scan_candidates(sources, workers)
    log.info("Found %d candidate clean files across %d sources", len(candidates), len(sources))

    # Build existing hash set in parallel
    print(C.info("Fingerprinting existing clean files..."))
    known = build_known_hashes(Config.CLEAN_DIR, workers)

    copied  = 0
    errors  = 0
    prog    = Progress(need, prefix="Collecting clean")

    # Process in batches for better memory + cache behaviour
    for batch_start in range(0, len(candidates), Config.BATCH_SIZE):
        if copied >= need:
            break
        batch = candidates[batch_start : batch_start + Config.BATCH_SIZE]

        # Hash entire batch in parallel
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_hash_worker, f): f for f in batch}
            for fut in as_completed(futures):
                if copied >= need:
                    break
                src, digest = fut.result()
                if digest is None or digest in known:
                    continue
                dst = Config.CLEAN_DIR / f"{src.stem}_{digest[:8]}{src.suffix.lower()}"
                try:
                    shutil.copy2(src, dst)
                    known.add(digest)
                    copied += 1
                    log.debug("Copied clean: %s", dst.name)
                    prog.update()
                except OSError as exc:
                    errors += 1
                    log.warning("Copy failed %s: %s", src, exc)

        get_hash_cache().flush()

    prog.finish()
    if errors:
        print(C.warn(f"{errors} files could not be copied (check log)"))
    print(C.ok(f"Collected {copied:,} new clean samples  ({existing + copied:,} total)"))


# ══════════════════════════════════════════════════════════════════════════════
#  DEDUPLICATION  (in-place, within each folder)
# ══════════════════════════════════════════════════════════════════════════════

def deduplicate(folder: Path, workers: int) -> int:
    """Remove duplicate PE files within *folder*. Returns number removed."""
    files = list(iter_pe(folder))
    if not files:
        return 0

    print(C.info(f"Deduplicating {folder.name}/ ({len(files):,} files)..."))
    seen:    dict[str, Path] = {}
    to_del:  list[Path]      = []
    prog     = Progress(len(files), prefix=f"Dedup {folder.name}")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_hash_worker, f): f for f in files}
        for fut in as_completed(futs):
            path, digest = fut.result()
            if digest is None:
                prog.update()
                continue
            if digest in seen:
                to_del.append(path)
                log.info("Duplicate: %s  (same as %s)", path.name, seen[digest].name)
            else:
                seen[digest] = path
            prog.update()

    prog.finish()
    get_hash_cache().flush()

    for p in to_del:
        try:
            p.unlink()
        except OSError:
            pass

    if to_del:
        print(C.ok(f"Removed {len(to_del):,} duplicate(s) from {folder.name}/"))
    else:
        print(C.ok(f"No duplicates in {folder.name}/"))

    return len(to_del)


# ══════════════════════════════════════════════════════════════════════════════
#  DATASET INDEX
# ══════════════════════════════════════════════════════════════════════════════

def build_index(workers: int, force: bool = False) -> list[FileRecord]:
    """
    Build (or reload) dataset_index.json.
    Scans malware/ and clean/ in parallel.
    If the index already exists and force=False, it is returned as-is.
    """
    if Config.INDEX_FILE.exists() and not force:
        try:
            with open(Config.INDEX_FILE, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            records = [FileRecord(**r) for r in raw]
            print(C.info(f"Loaded existing index: {len(records):,} records"))
            return records
        except Exception:
            pass

    print(C.info("Building dataset index..."))
    records: list[FileRecord] = []

    def _scan_label(folder: Path, label: str) -> list[FileRecord]:
        result = []
        files  = list(iter_pe(folder))
        if not files:
            return result
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_hash_worker, f): f for f in files}
            for fut in as_completed(futs):
                path, digest = fut.result()
                if digest:
                    try:
                        size = path.stat().st_size
                    except OSError:
                        size = 0
                    result.append(FileRecord(
                        filename = path.name,
                        sha256   = digest,
                        label    = label,
                        split    = "",          # assigned during split
                        size     = size,
                    ))
        return result

    records += _scan_label(Config.MALWARE_DIR, "malware")
    records += _scan_label(Config.CLEAN_DIR,   "clean")
    get_hash_cache().flush()

    _write_index(records)
    print(C.ok(f"Index built: {len(records):,} records → {Config.INDEX_FILE.name}"))
    return records


def _write_index(records: list[FileRecord]):
    tmp = Config.INDEX_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump([asdict(r) for r in records], fh, indent=2)
    tmp.replace(Config.INDEX_FILE)


# ══════════════════════════════════════════════════════════════════════════════
#  TRAIN / TEST SPLIT
# ══════════════════════════════════════════════════════════════════════════════

def build_split(records: list[FileRecord], ratio: float = Config.TRAIN_RATIO,
                workers: int = Config.WORKERS):
    """
    Stratified split (preserves class balance).
    Copies files into:
        dataset/train/malware/   dataset/train/clean/
        dataset/test/malware/    dataset/test/clean/
    """
    # Separate by label
    by_label: dict[str, list[FileRecord]] = {"malware": [], "clean": []}
    for r in records:
        if r.label in by_label:
            by_label[r.label].append(r)

    for label, recs in by_label.items():
        if not recs:
            continue
        random.shuffle(recs)
        n_train   = int(len(recs) * ratio)
        train_set = recs[:n_train]
        test_set  = recs[n_train:]

        for rec in train_set:
            rec.split = "train"
        for rec in test_set:
            rec.split = "test"

    # Source folders
    src_dir = {"malware": Config.MALWARE_DIR, "clean": Config.CLEAN_DIR}
    dst_dir = {
        ("train", "malware"): Config.TRAIN_DIR / "malware",
        ("train", "clean"):   Config.TRAIN_DIR / "clean",
        ("test",  "malware"): Config.TEST_DIR  / "malware",
        ("test",  "clean"):   Config.TEST_DIR  / "clean",
    }

    all_recs = [r for recs in by_label.values() for r in recs]
    prog     = Progress(len(all_recs), prefix="Building split")

    def _copy_record(rec: FileRecord):
        src = src_dir[rec.label] / rec.filename
        dst = dst_dir[(rec.split, rec.label)] / rec.filename
        if not src.exists():
            return
        if not dst.exists():
            try:
                shutil.copy2(src, dst)
            except OSError as exc:
                log.warning("Split copy failed %s: %s", src, exc)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_copy_record, r): r for r in all_recs}
        for _ in as_completed(futs):
            prog.update()

    prog.finish()

    # Persist updated split info to index
    _write_index(all_recs)

    # Summary
    for label in ("malware", "clean"):
        n_tr = sum(1 for r in by_label[label] if r.split == "train")
        n_te = sum(1 for r in by_label[label] if r.split == "test")
        print(C.ok(f"{label.capitalize():8s}  train={n_tr:,}  test={n_te:,}"))

    log.info("Split complete. train=%.0f%% test=%.0f%%", ratio*100, (1-ratio)*100)


# ══════════════════════════════════════════════════════════════════════════════
#  STATUS DISPLAY
# ══════════════════════════════════════════════════════════════════════════════

_QUALITY_THRESHOLDS = [
    (5000, "✓✓✓", "green",  "Professional"),
    (2000, "✓✓ ", "green",  "Excellent"),
    (1000, "✓  ", "green",  "Very good"),
    (500,  "✓  ", "cyan",   "Good"),
    (200,  "⚠  ", "yellow", "Fair  (aim for 500+ per class)"),
    (0,    "✗  ", "red",    "Too small  (need ≥200 per class)"),
]


def _quality_label(n: int) -> str:
    for threshold, icon, colour, label in _QUALITY_THRESHOLDS:
        if n >= threshold:
            fn = getattr(C, colour, C.dim)
            return fn(f"{icon} {label}")
    return C.red("✗   Too small")


def show_status():
    m  = count_pe(Config.MALWARE_DIR)
    c  = count_pe(Config.CLEAN_DIR)
    mt = count_pe(Config.TRAIN_DIR / "malware")
    ct = count_pe(Config.TRAIN_DIR / "clean")
    me = count_pe(Config.TEST_DIR  / "malware")
    ce = count_pe(Config.TEST_DIR  / "clean")

    W  = 58
    HR = "  " + "═" * W

    def row(label: str, value: str) -> str:
        return f"  ║  {label:<24}{value:<{W-26}}║"

    print()
    print("  " + C.bold("╔" + "═" * W + "╗"))
    print("  " + C.bold("║") + C.bold(f"{'  HEURISTIC SCANNER — DATASET STATUS':^{W}}") + C.bold("║"))
    print(HR)

    print(row("Malware samples:",   C.red(f"{m:>8,}")))
    print(row("Clean samples:",     C.green(f"{c:>8,}")))
    print(row("Total:",             C.bold(f"{m+c:>8,}")))
    print(HR)

    if m > 0 and c > 0:
        ratio = min(m, c) / max(m, c)
        bal_s = (C.green(f"✓  Balanced  ({ratio:.0%})")
                 if ratio >= Config.BALANCE_WARN
                 else C.yellow(f"⚠  Imbalanced  ({ratio:.0%})"))
        print(row("Balance:", bal_s))
        print(row("Quality:", _quality_label(min(m, c))))
    else:
        print(row("Status:", C.red("✗  Not enough data")))

    if mt + ct + me + ce > 0:
        print(HR)
        print(row("Train  malware/clean:", C.dim(f"{mt:,} / {ct:,}")))
        print(row("Test   malware/clean:", C.dim(f"{me:,} / {ce:,}")))

    print(HR)
    print(row("Index file:", C.dim("✓ exists") if Config.INDEX_FILE.exists() else C.yellow("⚠ not built")))
    print("  " + C.bold("╚" + "═" * W + "╝"))
    print()

    if m == 0:
        print(C.yellow("  ─── How to add malware samples ────────────────────────"))
        print(C.info("A) Drop .exe/.dll files into:  ai\\dataset\\malware\\"))
        print(C.info("B) Drop password-protected ZIPs — auto-extracted"))
        print(C.info("   Password 'infected' is tried automatically"))
        print(C.info("C) https://bazaar.abuse.ch/browse/  (download → paste ZIPs)"))
        print()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="HeuristicScanner — Dataset Setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--status",        action="store_true", help="Show status and exit")
    p.add_argument("--split",         action="store_true", help="(Re)build train/test split")
    p.add_argument("--collect-clean", action="store_true", help="Collect clean Windows PE samples")
    p.add_argument("--clean-target",  type=int, default=Config.CLEAN_TARGET,
                   help=f"Clean sample target (default {Config.CLEAN_TARGET})")
    p.add_argument("--workers",       type=int, default=Config.WORKERS,
                   help=f"Parallel workers (default {Config.WORKERS})")
    p.add_argument("--rebuild-index", action="store_true", help="Force rebuild dataset index")
    p.add_argument("--no-dedup",      action="store_true", help="Skip deduplication step")
    return p.parse_args()


def main():
    args    = parse_args()
    workers = args.workers
    t0      = time.monotonic()

    print()
    print(C.bold("  ═══════════════════════════════════════════════════════"))
    print(C.bold("  HeuristicScanner — Dataset Setup  v2.0"))
    print(C.bold("  ═══════════════════════════════════════════════════════"))
    print()

    ensure_folders()

    # ── Status only ──────────────────────────────────────────────────────────
    if args.status:
        show_status()
        return

    # ── Extract dropped ZIPs ─────────────────────────────────────────────────
    extract_zips(Config.MALWARE_DIR)
    extract_zips(Config.CLEAN_DIR)

    # ── Deduplication ────────────────────────────────────────────────────────
    if not args.no_dedup:
        deduplicate(Config.MALWARE_DIR, workers)
        deduplicate(Config.CLEAN_DIR,   workers)

    # ── Auto-collect clean samples ───────────────────────────────────────────
    collect_clean(target=args.clean_target, workers=workers)

    # ── Build / reload index ─────────────────────────────────────────────────
    records = build_index(workers=workers, force=args.rebuild_index)

    # ── Train/test split ─────────────────────────────────────────────────────
    if args.split or not (Config.TRAIN_DIR / "malware").iterdir().__next__() is None:
        try:
            # Only auto-split if train dirs are empty
            any_train = any(True for _ in (Config.TRAIN_DIR / "malware").iterdir())
        except StopIteration:
            any_train = False
        except OSError:
            any_train = False

        if args.split or not any_train:
            print(C.info("Building train/test split..."))
            build_split(records, workers=workers)

    # ── Final status ─────────────────────────────────────────────────────────
    show_status()

    elapsed = time.monotonic() - t0
    print(C.ok(f"Finished in {elapsed:.1f}s"))
    print(C.info("Next: run  train.bat  to train the model"))
    print()

    get_hash_cache().flush()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C.yellow("\n\n  Interrupted — flushing cache..."))
        try:
            get_hash_cache().flush()
        except Exception:
            pass
        sys.exit(0)
    except Exception as exc:
        print(C.err(f"Fatal error: {exc}"))
        log.exception("Fatal error")
        sys.exit(1)
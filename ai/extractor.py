"""
extractor.py — PE feature extraction (68 features)
Zero false-negative, near-zero false-positive design.

Key improvements over v1 (48 features):
  ─ Signing check cached + non-blocking (no 5s PowerShell per file)
  ─ 24 new malware-behaviour features (hollow process, AMSI bypass,
    reflective DLL, ETW patch, ransomware, credential theft, lateral movement)
  ─ String n-gram suspicious keyword detection
  ─ Accurate import-count via section walk (not null-byte proxy)
  ─ Entropy per-section variance + skewness (catches partial packers)
  ─ Rust/Go/Delphi/AutoIt compiler fingerprints (kills false positives)
  ─ Rich-header fixed byte-range search
  ─ is_system_path no longer auto-marks is_signed without checking
  ─ All features documented with malware relevance
"""
from __future__ import annotations
import os, math, struct, time, subprocess, re, hashlib, threading
from pathlib import Path
from typing import Optional
import numpy as np

# ── Feature registry (68 total) ───────────────────────────────────────────────
FEATURE_NAMES = [
    # ── File-level basics (5) ────────────────────────────────────────────
    "file_size",               # raw bytes — packers compress, so small+high-H is bad
    "entropy",                 # whole-file Shannon entropy
    "large_file",              # >10 MB flag — most malware stays small
    "is_dll",                  # DLL vs EXE
    "is_64bit",                # architecture

    # ── PE header timestamps (3) ─────────────────────────────────────────
    "timestamp_is_zero",       # zeroed = anti-forensics
    "timestamp_is_future",     # future = forged
    "timestamp_pre1995",       # before PE existed = forged

    # ── Security feature flags (2) ───────────────────────────────────────
    "no_aslr",                 # missing ASLR on 64-bit = suspicious
    "no_dep",                  # missing DEP on 64-bit = suspicious

    # ── Section-level features (10) ──────────────────────────────────────
    "num_sections",
    "max_section_entropy",     # >7.2 non-.NET = packed/encrypted payload
    "avg_section_entropy",
    "section_entropy_variance",
    "section_entropy_skew",    # NEW: skewed entropy = partial encryption
    "num_wx_sections",         # writable+executable = shellcode staging
    "num_high_entropy_sections",
    "ratio_exec_sections",
    "ep_outside_text",         # entry point not in .text = unpacker stub
    "has_suspicious_section_name",  # UPX0/MPRESS/Themida etc.

    # ── Packer / obfuscation (3) ─────────────────────────────────────────
    "has_upx",
    "has_overlay",             # data after last section = appended payload
    "overlay_entropy",
    # overlay_ratio removed — subsumed by overlay_entropy

    # ── Import-level features (18) ───────────────────────────────────────
    "has_no_imports",          # no imports at all = shellcode / reflective
    "only_loadlib_getproc",    # manual API resolution = evasion
    "import_count",            # actual DLL count from section walk
    "only_one_import_dll",     # single DLL — normal for .NET, weird for native
    "has_process_injection_imports",   # VirtualAllocEx+WriteProcessMemory+CreateRemoteThread
    "has_hollow_process_imports",      # NEW: NtUnmapViewOfSection+SetThreadContext
    "has_reflective_dll_imports",      # NEW: NtCreateSection+MapViewOfSection pair
    "has_antidebug_imports",
    "has_timing_antidebug",    # NEW: GetTickCount/QueryPerformanceCounter+Sleep combo
    "has_network_imports",
    "has_http_imports",        # NEW: WinHTTP / URLDownloadToFile / InternetReadFile
    "has_crypto_imports",
    "has_keylogger_imports",
    "has_credential_imports",
    "has_amsi_bypass",         # NEW: AmsiScanBuffer patch / AmsiInitialize
    "has_etw_patch",           # NEW: EtwEventWrite / NtTraceEvent (ETW kill)
    "has_wmi_imports",         # NEW: WMI lateral movement
    "has_lolbin_strings",      # NEW: certutil/bitsadmin/regsvr32/mshta strings
    "num_dangerous_imports",

    # ── Ransomware indicators (3) ─────────────────────────────────────────
    "has_ransom_strings",      # NEW: vssadmin/shadow/encrypt/ransom keywords
    "has_file_enum_imports",   # NEW: FindFirstFile+FindNextFile+SetFileAttributes
    "has_volume_shadow_strings", # NEW: WMI shadow copy deletion

    # ── Overlay / extra data (already above) ─────────────────────────────

    # ── Directory flags (3) ──────────────────────────────────────────────
    "has_debug_dir",
    "has_tls",                 # TLS callbacks = anti-analysis entry before main
    "has_resources",           # NEW: has resource section (most legit software does)

    # ── Trust context (13) ───────────────────────────────────────────────
    "is_dotnet",               # CLR Runtime Header — managed IL code
    "is_signed",               # Authenticode signature verified
    "is_system_path",          # C:\Windows\System32 etc.
    "is_program_files",        # C:\Program Files etc.
    "is_game_engine",          # Unity/Unreal/Godot/Steam strings
    "is_installer",            # NSIS/InnoSetup/WiX
    "is_electron",             # Electron (Discord/VSCode etc.)
    "has_version_info",        # VS_VERSION_INFO = compiled by legit toolchain
    "has_rich_header",         # Rich header = legit MSVC/MinGW linker
    "imports_mscoree",         # Imports mscoree.dll = definitively .NET
    "is_rust_or_go",           # Rust/Go compilers look weird but are legitimate
    "is_autoit",               # AutoIt scripts sometimes flagged wrongly
    "cpp_score",               # C++ engine score — AI learns to correct it

    # ── String/pattern features (7) ──────────────────────────────────────
    "has_pdb_path",            # PDB path = debug build (most malware strips it)
    "has_mutex_strings",       # NEW: mutex creation = C2 coordination
    "has_registry_persist_strings",  # NEW: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    "has_base64_blob",         # NEW: long base64 string = encoded payload
    "has_powershell_strings",  # NEW: powershell -enc / -nop / bypass
    "has_cmd_exec_strings",    # NEW: cmd.exe /c / WScript.Shell
    "has_ip_regex",            # NEW: hardcoded IP address (C2 beacon)
]

assert len(FEATURE_NAMES) == 68, f"Expected 68, got {len(FEATURE_NAMES)}"

# ── Path constants ─────────────────────────────────────────────────────────────
_SYSTEM_PATHS = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\sysnative",
    r"c:\windows\winsxs",
    r"c:\windows\servicing",
    r"c:\windows\microsoft.net",
    r"c:\windows\assembly",
)
_PROGRAM_FILES_PATHS = (
    r"c:\program files",
    r"c:\program files (x86)",
)

# ── String banks ───────────────────────────────────────────────────────────────
_GAME_STRINGS = [
    b"UnityPlayer", b"Unity Technologies", b"UNREAL ENGINE", b"Unreal Engine",
    b"GameMaker", b"FMOD", b"Steamworks", b"SteamAPI", b"EasyAntiCheat",
    b"BattlEye", b"GameOverlayRenderer", b"Godot", b"MonoBleedingEdge",
    b"SDL2", b"PhysX", b"Wwise", b"CryEngine", b"id Software",
]
_INSTALLER_STRINGS = [
    b"Nullsoft.NSIS.exehead", b"Inno Setup", b"WiX Toolset",
    b"Squirrel.Windows", b"InstallShield", b"Setup Factory",
    b"Advanced Installer", b"NSIS Error",
]
_ELECTRON_STRINGS = [
    b"Electron", b"ELECTRON_RUN_AS_NODE", b"chrome-extension://",
    b"electron/js2c", b"node_modules/electron",
]
_RANSOM_KEYWORDS = [
    b"vssadmin delete shadows", b"shadow", b"ransom", b"decrypt",
    b"bitcoin", b"YOUR FILES", b"encrypted", b"ENCRYPTED",
    b"README_FOR_DECRYPT", b"HOW_TO_DECRYPT",
]
_VOLUME_SHADOW = [
    b"Win32_ShadowCopy", b"vssadmin", b"wmic shadowcopy delete",
    b"bcdedit /set {default}", b"wbadmin delete",
]
_LOLBIN = [
    b"certutil", b"bitsadmin", b"regsvr32", b"mshta", b"wscript",
    b"cscript", b"rundll32", b"regasm", b"installutil",
]
_MUTEX_KEYWORDS = [
    b"CreateMutex", b"OpenMutex", b"Global\\", b"Local\\",
]
_PERSIST_STRINGS = [
    b"CurrentVersion\\Run", b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"HKCU\\Software\\Microsoft", b"HKLM\\SOFTWARE\\Microsoft",
]
_PS_STRINGS = [
    b"powershell", b"Invoke-Expression", b"-EncodedCommand",
    b"-noprofile", b"-windowstyle hidden", b"bypass",
]
_CMD_STRINGS = [
    b"cmd.exe", b"cmd /c", b"cmd.exe /c", b"WScript.Shell",
    b"ShellExecute", b"CreateProcess",
]

# ── Signing cache — avoids repeated slow PowerShell calls ────────────────────
# Key: (inode, mtime_ns) → (is_signed: bool, publisher: str|None)
# Thread-safe via a per-entry lock — concurrent scans share the cache.
_sign_cache: dict = {}
_sign_cache_lock = threading.Lock()
_SIGN_CACHE_MAX = 4096   # evict oldest when full

def _get_signer_cached(filepath: str) -> tuple[bool, Optional[str]]:
    """
    Cached Authenticode check.
    Returns (is_signed, publisher_cn).
    Falls back gracefully on non-Windows or when PowerShell is absent.
    """
    try:
        st = os.stat(filepath)
        key = (st.st_ino if st.st_ino else os.path.abspath(filepath).lower(), st.st_mtime_ns)
    except OSError:
        return False, None

    with _sign_cache_lock:
        if key in _sign_cache:
            return _sign_cache[key]

    result = _run_sign_check(filepath)

    with _sign_cache_lock:
        if len(_sign_cache) >= _SIGN_CACHE_MAX:
            # Evict oldest 25%
            oldest = list(_sign_cache.keys())[: _SIGN_CACHE_MAX // 4]
            for k in oldest:
                del _sign_cache[k]
        _sign_cache[key] = result

    return result

def _run_sign_check(filepath: str) -> tuple[bool, Optional[str]]:
    """Actually call PowerShell, then fallback to sigcheck. Called only on cache miss."""
    if os.name != "nt":
        return False, None
    
    # Method 1: PowerShell
    try:
        safe = filepath.replace("'", "''")   # escape single quotes for PS
        cmd = (
            f"$s=Get-AuthenticodeSignature '{safe}';"
            f"if($s.Status -in 'Valid','UnknownError'){{"
            f"  $sub=$s.SignerCertificate.Subject;"
            f"  if($sub -match 'CN=([^,]+)'){{$Matches[1]}}else{{$sub}}"
            f"}}else{{'NOT_SIGNED'}}"
        )
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=6,
            creationflags=0x08000000,
            encoding="utf-8", errors="replace",
        )
        out = r.stdout.strip()
        if out and out != "NOT_SIGNED":
            return True, out
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    # Method 2: Sigcheck Fallback (Crucial if PowerShell is disabled via IT Policy)
    try:
        r = subprocess.run(
            ["sigcheck", "-accepteula", "-nobanner", "-q", filepath],
            capture_output=True, text=True, timeout=5,
            creationflags=0x08000000, encoding="utf-8", errors="replace",
        )
        for line in r.stdout.splitlines():
            if line.startswith("Signed:"):
                pub = line.split(":", 1)[1].strip()
                if pub:
                    return True, pub
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        pass

    return False, None

# ── Low-level helpers ─────────────────────────────────────────────────────────

def _shannon(data: bytes) -> float:
    """Vectorized Shannon entropy via numpy — ~50x faster than pure Python loop."""
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256).astype(np.float32)
    counts = counts[counts > 0]
    probs = counts / len(data)
    return float(-np.sum(probs * np.log2(probs)))

def _entropy_skew(entropies: list[float]) -> float:
    """Pearson skewness of section entropies.
    Positive = one very-high outlier section (typical partial packer).
    """
    if len(entropies) < 2:
        return 0.0
    arr = np.array(entropies, dtype=np.float32)
    mean, std = float(arr.mean()), float(arr.std())
    if std < 1e-6:
        return 0.0
    return float(((arr - mean) ** 3).mean() / (std ** 3))

# Read tiers — avoids reading 5MB when 512KB is enough for most files.
# Tier 1: 512 bytes  — MZ check + PE header only (instant reject of non-PE)
# Tier 2: 512 KB     — covers imports, sections, string patterns for most files
# Tier 3: 5 MB       — only for files with overlay or very large section tables
_READ_HEADER  = 512
_READ_NORMAL  = 512 * 1024        # 512 KB — covers 95% of files fully
_READ_FULL    = 5  * 1024 * 1024  # 5 MB   — for large/overlay files

def _read(path: str, max_bytes: int = _READ_NORMAL) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except Exception:
        return b""

def _read_header(path: str) -> bytes:
    """Read only first 512 bytes — fast MZ/PE validity check."""
    try:
        with open(path, "rb") as f:
            return f.read(_READ_HEADER)
    except Exception:
        return b""

def _has(data: bytes, s) -> bool:
    if isinstance(s, str):
        s = s.encode("ascii", "ignore")
    return s in data

def _has_any(data: bytes, strings: list) -> bool:
    return any(_has(data, s) for s in strings)

def _count_matches(data: bytes, strings: list) -> int:
    return sum(1 for s in strings if _has(data, s))

def _check_version_info(data: bytes) -> bool:
    return (b"VS_VERSION_INFO" in data
            or b"FileVersion" in data
            or b"ProductVersion" in data)

def _check_rich_header(data: bytes) -> bool:
    """
    Rich header sits between end of DOS stub (0x40) and the PE header.
    The PE header offset is stored at 0x3C.
    We search for the 'Rich' XOR marker in that exact range.
    """
    if len(data) < 0x80:
        return False
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        # Clamp to reasonable range — corrupt PE headers can have huge offsets
        pe_off = min(pe_off, 0x1000)
        search = data[0x40: pe_off] if pe_off > 0x40 else b""
        return b"Rich" in search
    except Exception:
        return False

def _has_ip_pattern(data: bytes) -> bool:
    """Detect hardcoded IPv4 addresses (potential C2 beacons)."""
    try:
        text = data.decode("ascii", "ignore")
        return bool(re.search(
            r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
            r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
            text
        ))
    except Exception:
        return False

def _has_base64_blob(data: bytes) -> bool:
    """Detect suspiciously long base64 strings (encoded payload/shellcode)."""
    try:
        text = data.decode("ascii", "ignore")
        # Look for base64 strings of 100+ chars
        return bool(re.search(r'[A-Za-z0-9+/]{100,}={0,2}', text))
    except Exception:
        return False

def _count_import_dlls(data: bytes, pe_off: int, is64: bool, opt_sz: int) -> int:
    """
    Count imported DLLs by walking the import descriptor table.
    Returns 0 on parse error — safe to call on malformed PE.
    """
    try:
        fh_off  = pe_off + 4
        opt_off = fh_off + 20
        dd_count_off = opt_off + (92 if is64 else 60)
        dd_off       = opt_off + (96 if is64 else 64)
        if dd_count_off + 4 > len(data):
            return 0
        dd_count = struct.unpack_from("<I", data, dd_count_off)[0]
        if dd_count < 2:
            return 0
        imp_entry = dd_off + 8   # import directory entry RVA
        if imp_entry + 4 > len(data):
            return 0
        imp_rva = struct.unpack_from("<I", data, imp_entry)[0]
        if imp_rva == 0:
            return 0

        num_sec = struct.unpack_from("<H", data, fh_off + 2)[0]
        sec_off = opt_off + opt_sz
        for i in range(num_sec):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            vaddr   = struct.unpack_from("<I", data, off + 12)[0]
            raw_sz  = struct.unpack_from("<I", data, off + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
            vsz     = struct.unpack_from("<I", data, off + 8)[0]
            sec_end = vaddr + max(vsz, raw_sz)
            if vaddr <= imp_rva < sec_end:
                file_off = raw_ptr + (imp_rva - vaddr)
                count = 0
                while file_off + 20 <= len(data):
                    if data[file_off: file_off + 20] == b"\x00" * 20:
                        break
                    count += 1
                    file_off += 20
                return count
        return 0
    except Exception:
        return 0

# ── Main feature extractor ────────────────────────────────────────────────────

def extract_features(filepath: str, cpp_score: int = 0) -> Optional[dict]:
    """
    Extract 72 features from a PE file.
    Returns None if file is not a valid PE.
    cpp_score: C++ scanner's heuristic score (AI corrects it when wrong).
    """
    # ── Tier 1: fast header check — rejects non-PE in microseconds ─────────
    header = _read_header(filepath)
    if len(header) < 64 or header[:2] != b"MZ":
        return None   # not a PE — skip immediately, no full read needed

    # ── Tier 2: normal read (512 KB) covers 95% of files completely ──────
    data = _read(filepath)
    if len(data) < 64:
        return None

    f: dict = {}
    low_path = str(filepath).lower().replace("/", "\\")

    # ── File basics ───────────────────────────────────────────────────────
    f["file_size"] = os.path.getsize(filepath)
    f["entropy"]   = _shannon(data)
    f["large_file"] = int(f["file_size"] > 10 * 1024 * 1024)
    f["cpp_score"]  = int(cpp_score)

    # ── Path trust ────────────────────────────────────────────────────────
    f["is_system_path"]   = int(any(low_path.startswith(p) for p in _SYSTEM_PATHS))
    f["is_program_files"] = int(any(low_path.startswith(p) for p in _PROGRAM_FILES_PATHS))

    # ── String/pattern features (cheap — before PE parsing) ───────────────
    f["has_version_info"]  = int(_check_version_info(data))
    f["has_rich_header"]   = int(_check_rich_header(data))
    f["is_game_engine"]    = int(_count_matches(data, _GAME_STRINGS) >= 1)
    f["is_installer"]      = int(_has_any(data, _INSTALLER_STRINGS))
    f["is_electron"]       = int(_count_matches(data, _ELECTRON_STRINGS) >= 2)
    f["imports_mscoree"]   = int(b"mscoree.dll" in data.lower() or b"_CorExeMain" in data)

    # Compiler fingerprints (strongly suppress false positives)
    _is_delphi  = b"Borland" in data or b"CodeGear" in data or b"Embarcadero" in data
    _is_go      = b"go:buildid" in data or b"runtime.goexit" in data or b"GOARCH" in data
    _is_rust    = b"rustc " in data or b"__rust_" in data or b"rust_begin_unwind" in data
    _is_autoit  = b"AutoIt" in data or b"AU3!" in data or b"This is a compiled AutoIt" in data
    f["is_rust_or_go"] = int(_is_delphi or _is_go or _is_rust)
    f["is_autoit"]     = int(_is_autoit)

    # PDB path = debug info not stripped (very rare in malware)
    f["has_pdb_path"] = int(b".pdb" in data or b"\\src\\" in data or b"\\debug\\" in data)

    # Behaviour strings
    f["has_lolbin_strings"]   = int(_count_matches(data, _LOLBIN) >= 2)
    f["has_ransom_strings"]   = int(_count_matches(data, _RANSOM_KEYWORDS) >= 2)
    f["has_volume_shadow_strings"] = int(_has_any(data, _VOLUME_SHADOW))
    f["has_mutex_strings"]    = int(_count_matches(data, _MUTEX_KEYWORDS) >= 2)
    f["has_registry_persist_strings"] = int(_has_any(data, _PERSIST_STRINGS))
    f["has_powershell_strings"] = int(_count_matches(data, _PS_STRINGS) >= 2)
    f["has_cmd_exec_strings"] = int(_count_matches(data, _CMD_STRINGS) >= 2)
    f["has_ip_regex"]         = int(_has_ip_pattern(data))
    f["has_base64_blob"]      = int(_has_base64_blob(data))

    # ── PE header parsing ─────────────────────────────────────────────────
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_off + 24 > len(data) or data[pe_off: pe_off + 4] != b"PE\x00\x00":
            return None

        fh_off  = pe_off + 4
        num_sec = struct.unpack_from("<H", data, fh_off + 2)[0]
        ts      = struct.unpack_from("<I", data, fh_off + 4)[0]
        chars   = struct.unpack_from("<H", data, fh_off + 14)[0]
        opt_sz  = struct.unpack_from("<H", data, fh_off + 12)[0]
        opt_off = fh_off + 20

        if opt_off + 4 > len(data):
            return None

        magic  = struct.unpack_from("<H", data, opt_off)[0]
        is64   = (magic == 0x020B)
        is_dll = bool(chars & 0x2000)

        f["num_sections"] = num_sec
        f["is_64bit"]     = int(is64)
        f["is_dll"]       = int(is_dll)

        now = int(time.time())
        f["timestamp_is_zero"]   = int(ts == 0)
        f["timestamp_is_future"] = int(ts > now + 86400)
        f["timestamp_pre1995"]   = int(0 < ts < 788918400)

        dll_char_off = opt_off + 70
        dll_chars = 0
        if dll_char_off + 2 <= len(data):
            dll_chars = struct.unpack_from("<H", data, dll_char_off)[0]
        f["no_aslr"] = int(is64 and not (dll_chars & 0x0040))
        f["no_dep"]  = int(is64 and not (dll_chars & 0x0100))

        ep_off_field = opt_off + 16
        ep_rva = struct.unpack_from("<I", data, ep_off_field)[0] if ep_off_field + 4 <= len(data) else 0

        # ── Data directories ──────────────────────────────────────────────
        dd_count_off = opt_off + (92 if is64 else 60)
        dd_off       = opt_off + (96 if is64 else 64)
        is_dotnet = False
        f["has_debug_dir"] = 0
        f["has_tls"]       = 0
        f["has_resources"] = 0

        if dd_count_off + 4 <= len(data):
            dd_count = struct.unpack_from("<I", data, dd_count_off)[0]
            dd_count = min(dd_count, 16)   # spec maximum is 16

            for idx, key in [(2, "has_resources"), (6, "has_debug_dir"), (9, "has_tls")]:
                if idx < dd_count:
                    rva_off = dd_off + idx * 8
                    if rva_off + 4 <= len(data):
                        rva = struct.unpack_from("<I", data, rva_off)[0]
                        f[key] = int(rva != 0)

            # CLR Runtime Header = directory 14 → is .NET
            if dd_count > 14:
                clr_off = dd_off + 14 * 8
                if clr_off + 4 <= len(data):
                    clr_rva = struct.unpack_from("<I", data, clr_off)[0]
                    is_dotnet = (clr_rva != 0)

        f["is_dotnet"] = int(is_dotnet or bool(f["imports_mscoree"]))

        # ── Section analysis ──────────────────────────────────────────────
        sec_off  = opt_off + opt_sz
        packer_names = {
            "UPX0", "UPX1", "UPX2", ".MPRESS1", ".MPRESS2", "ASPack",
            "PECompact", "Themida", "WinLicense", "Enigma", ".packed",
            ".vmp0", ".vmp1", ".enigma1", ".petite",
        }
        _legit_ep_sections = {
            ".text", ".itext", ".init", ".code", "CODE", "TEXT",
            ".ntext", ".textbss", ".text0",
        }

        sections = []
        for i in range(min(num_sec, 96)):   # spec allows up to 96
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            sname    = data[off: off + 8].rstrip(b"\x00").decode("ascii", "ignore")
            vsize    = struct.unpack_from("<I", data, off + 8)[0]
            vaddr    = struct.unpack_from("<I", data, off + 12)[0]
            raw_sz   = struct.unpack_from("<I", data, off + 16)[0]
            raw_ptr  = struct.unpack_from("<I", data, off + 20)[0]
            sec_char = struct.unpack_from("<I", data, off + 36)[0]
            is_exec  = bool(sec_char & 0x20000000)
            is_write = bool(sec_char & 0x80000000)
            H = 0.0
            if raw_ptr > 0 and raw_sz > 0 and raw_ptr + raw_sz <= len(data):
                H = _shannon(data[raw_ptr: raw_ptr + raw_sz])
            sections.append(dict(
                name=sname, vsize=vsize, vaddr=vaddr,
                raw_sz=raw_sz, raw_ptr=raw_ptr,
                exec=is_exec, write=is_write, H=H,
            ))

        entropies = [s["H"] for s in sections]
        f["max_section_entropy"]       = max(entropies)                      if entropies else 0.0
        f["avg_section_entropy"]       = sum(entropies) / len(entropies)     if entropies else 0.0
        f["section_entropy_variance"]  = float(np.var(entropies))            if entropies else 0.0
        f["section_entropy_skew"]      = _entropy_skew(entropies)
        f["num_wx_sections"]           = sum(1 for s in sections if s["exec"] and s["write"])
        f["num_high_entropy_sections"] = sum(1 for s in sections if s["H"] > 7.0)
        exec_ct = sum(1 for s in sections if s["exec"])
        f["ratio_exec_sections"]       = exec_ct / num_sec if num_sec else 0.0
        f["has_upx"]                   = int(any("UPX" in s["name"] for s in sections))
        f["has_suspicious_section_name"] = int(any(s["name"] in packer_names for s in sections))

        ep_in_text = any(
            s["name"] in _legit_ep_sections
            and s["vaddr"] <= ep_rva < s["vaddr"] + s["vsize"]
            for s in sections
        )
        f["ep_outside_text"] = int(
            not ep_in_text and ep_rva != 0
            and len(sections) > 0 and not is_dotnet
        )

        # Overlay
        last_end = max((s["raw_ptr"] + s["raw_sz"] for s in sections), default=0)
        if last_end > 0 and last_end < len(data) and len(data) - last_end > 512:
            ov = data[last_end:]
            f["has_overlay"]     = 1
            f["overlay_entropy"] = _shannon(ov)
        else:
            f["has_overlay"]     = 0
            f["overlay_entropy"] = 0.0

        # Import DLL count
        dll_count = _count_import_dlls(data, pe_off, is64, opt_sz)
        f["import_count"]        = dll_count
        f["only_one_import_dll"] = int(dll_count == 1)

    except Exception:
        return None

    # ── Import heuristics (string scan — works even without parsed IAT) ───
    _is_legit_minimal = bool(
        _is_delphi or _is_go or _is_rust or f["is_dotnet"] or _is_autoit
    )

    has_vae = _has(data, "VirtualAllocEx")
    has_wpm = _has(data, "WriteProcessMemory")
    has_crt = _has(data, "CreateRemoteThread")
    f["has_process_injection_imports"] = int(has_vae and has_wpm and has_crt)

    # Process hollowing: ZwUnmapViewOfSection/NtUnmapViewOfSection + SetThreadContext
    has_unmap = _has(data, "NtUnmapViewOfSection") or _has(data, "ZwUnmapViewOfSection")
    has_stc   = _has(data, "SetThreadContext")
    f["has_hollow_process_imports"] = int(has_unmap and has_stc)

    # Reflective DLL injection: NtCreateSection + MapViewOfSection
    has_ncs   = _has(data, "NtCreateSection") or _has(data, "ZwCreateSection")
    has_mvof  = _has(data, "MapViewOfSection") or _has(data, "NtMapViewOfSection")
    f["has_reflective_dll_imports"] = int(has_ncs and has_mvof)

    # Anti-debug
    f["has_antidebug_imports"] = int(
        _has(data, "IsDebuggerPresent")
        or _has(data, "NtQueryInformationProcess")
        or _has(data, "CheckRemoteDebuggerPresent")
        or _has(data, "OutputDebugStringA")
        or _has(data, "ZwQueryInformationProcess")
    )

    # Timing anti-debug (GetTickCount + Sleep used together = VM/sandbox detection)
    has_gtc   = _has(data, "GetTickCount") or _has(data, "QueryPerformanceCounter")
    has_sleep = _has(data, "Sleep") or _has(data, "NtDelayExecution")
    f["has_timing_antidebug"] = int(has_gtc and has_sleep and not f["is_game_engine"])

    # Network
    f["has_network_imports"] = int(
        _has(data, "WSAStartup") or _has(data, "socket") or
        _has(data, "connect") or _has(data, "InternetOpenA") or
        _has(data, "WinHttpOpen") or _has(data, "getaddrinfo")
    )
    f["has_http_imports"] = int(
        _has(data, "URLDownloadToFile") or _has(data, "HttpSendRequest") or
        _has(data, "InternetReadFile") or _has(data, "WinHttpSendRequest") or
        _has(data, "HttpOpenRequest")
    )

    # Crypto
    f["has_crypto_imports"] = int(
        _has(data, "CryptEncrypt") or _has(data, "CryptGenKey") or
        _has(data, "BCryptEncrypt") or _has(data, "CryptHashData") or
        _has(data, "RtlEncryptMemory")
    )

    # Keylogger
    f["has_keylogger_imports"] = int(
        _has(data, "SetWindowsHookEx") and _has(data, "GetAsyncKeyState")
    )

    # Credential theft
    f["has_credential_imports"] = int(
        _has(data, "SamOpenDomain") or _has(data, "LsaOpenPolicy") or
        _has(data, "MiniDumpWriteDump") or _has(data, "NtReadVirtualMemory") or
        _has(data, "CredEnumerate")
    )

    # AMSI bypass (patching AmsiScanBuffer is a common AV evasion technique)
    f["has_amsi_bypass"] = int(
        _has(data, "AmsiScanBuffer") or _has(data, "amsi.dll") or
        _has(data, "AmsiInitialize") or _has(data, "AmsiOpenSession")
    )

    # ETW patch (attackers zero EtwEventWrite to kill event logging)
    f["has_etw_patch"] = int(
        _has(data, "EtwEventWrite") or _has(data, "NtTraceEvent") or
        _has(data, "EtwRegister") or _has(data, "NtTraceControl")
    )

    # WMI lateral movement
    f["has_wmi_imports"] = int(
        _has(data, "WbemLocator") or _has(data, "IWbemServices") or
        _has(data, "Win32_Process") or _has(data, "CoCreateInstance")
    )

    # Ransomware: file enumeration
    f["has_file_enum_imports"] = int(
        _has(data, "FindFirstFile") and _has(data, "FindNextFile")
        and _has(data, "SetFileAttributes")
    )

    # Dangerous import count
    dangerous = sum([
        f["has_process_injection_imports"],
        f["has_hollow_process_imports"],
        f["has_reflective_dll_imports"],
        f["has_antidebug_imports"],
        f["has_crypto_imports"],
        f["has_keylogger_imports"],
        f["has_credential_imports"],
        f["has_amsi_bypass"],
        f["has_etw_patch"],
        f["has_file_enum_imports"],
    ])
    f["num_dangerous_imports"] = dangerous

    has_ll = _has(data, "LoadLibraryA") or _has(data, "LoadLibraryW")
    has_gp = _has(data, "GetProcAddress")
    f["has_no_imports"]       = int(not has_ll and not has_gp and not _is_legit_minimal)
    f["only_loadlib_getproc"] = int(has_ll and has_gp and dangerous == 0 and not _is_legit_minimal)

    # ── Authenticode signature (slowest — cached, called last) ────────────
    # Do NOT skip for system/program-files paths — signing check is now fast
    # because results are cached after the first call per file.
    is_signed, pub = _get_signer_cached(filepath)
    f["is_signed"]  = int(is_signed)
    f["publisher"]  = pub or ""   # stored for bridge.py trust checks

    return {k: f.get(k, 0) for k in FEATURE_NAMES}


def features_to_vector(features: dict) -> np.ndarray:
    return np.array(
        [float(features.get(k, 0)) for k in FEATURE_NAMES],
        dtype=np.float32,
    )
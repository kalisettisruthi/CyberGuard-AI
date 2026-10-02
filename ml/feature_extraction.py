# ml/feature_extraction.py
"""
Feature extraction for AI Cyber Threat Detection System.

Two functions:
  - extract_url_features(url)  -> 13 numeric features from a URL
  - extract_pe_features(path)  -> 7 numeric features from a PE (EXE) file

No model training. No Flask. Just pure feature extraction.
"""

import math
import re
from urllib.parse import urlparse
from pathlib import Path

import numpy as np

try:
    import pefile
    PEFILE_OK = True
except ImportError:
    PEFILE_OK = False


# Words often used in phishing URLs
SUSPICIOUS_WORDS = ["login", "verify", "account", "bank", "signin", "secure"]

# Suspicious top-level domains frequently used by phishing
SUSPICIOUS_TLDS = (".xyz", ".top", ".club", ".tk", ".work",
                   ".click", ".gq", ".ml", ".cf", ".ga", ".zip")

# Windows API imports commonly seen in malware
SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
    "CreateRemoteThread", "LoadLibrary", "GetProcAddress",
    "SetWindowsHookEx", "RegSetValue", "ShellExecute",
    "WinExec", "CreateProcess", "URLDownloadToFile",
    "InternetOpen", "HttpSendRequest", "CryptEncrypt",
}


# ------------------------------------------------------------------
# URL FEATURES  (13 features)
# ------------------------------------------------------------------
def extract_url_features(url: str) -> np.ndarray:
    """Return a 13-value numeric vector describing the given URL."""
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()

        features = [
            # 1-5: structural length / char stats
            len(url),
            url.count("."),
            url.count("-"),
            sum(c.isdigit() for c in url),
            sum(not c.isalnum() for c in url),

            # 6-8: protocol / host
            1 if parsed.scheme == "https" else 0,
            1 if _is_ip(netloc) else 0,
            netloc.count("."),

            # 9: suspicious keyword count
            sum(w in url.lower() for w in SUSPICIOUS_WORDS),

            # 10: domain length
            len(netloc),

            # 11: hyphen in the domain (e.g. "paypal-secure.xyz")
            1 if "-" in netloc else 0,

            # 12: suspicious TLD
            1 if netloc.endswith(SUSPICIOUS_TLDS) else 0,

            # 13: number of path segments (e.g. /a/b/c -> 3)
            len([s for s in path.split("/") if s]),
        ]
        return np.array(features, dtype=float)
    except Exception:
        return np.zeros(13, dtype=float)


def _is_ip(host: str) -> bool:
    """True if host looks like an IPv4 address."""
    host = host.split(":")[0]
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


# ------------------------------------------------------------------
# PE / EXE FEATURES  (7 features) — matches the Kaggle-trained model
# ------------------------------------------------------------------
def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string (0 to 8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def extract_pe_features(file_path) -> np.ndarray:
    """
    Statically analyse a PE file and return 7 numeric features
    that match the Kaggle-trained malware model.
    Returns zeros if the file is not a valid PE.
    """
    if not PEFILE_OK:
        return np.zeros(7, dtype=float)

    path = Path(file_path)
    if not path.exists():
        return np.zeros(7, dtype=float)

    try:
        # --- read raw bytes for entropy ---
        raw = path.read_bytes()
        entropy = _shannon_entropy(raw)

        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()

        size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
        major_linker = pe.OPTIONAL_HEADER.MajorLinkerVersion
        num_sections = pe.FILE_HEADER.NumberOfSections

        # suspicious imports
        suspicious_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode(errors="ignore")
                        if name in SUSPICIOUS_IMPORTS:
                            suspicious_count += 1

        # digital signature (security directory is index 4)
        is_signed = 0
        try:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if sec_dir.VirtualAddress != 0 and sec_dir.Size > 0:
                is_signed = 1
        except Exception:
            pass

        # debug data size (debug directory is index 6)
        debug_size = 0
        try:
            debug_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6]
            debug_size = debug_dir.Size
        except Exception:
            pass

        pe.close()

        return np.array(
            [
                float(size_of_code),
                float(major_linker),
                float(entropy),
                float(num_sections),
                float(suspicious_count),
                float(is_signed),
                float(debug_size),
            ],
            dtype=float,
        )
    except Exception:
        return np.zeros(7, dtype=float)


# ------------------------------------------------------------------
# Feature name lists
# ------------------------------------------------------------------
URL_FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_digits",
    "num_special", "has_https", "is_ip", "num_subdomains",
    "suspicious_words", "domain_length",
    "hyphen_in_domain", "suspicious_tld", "path_depth",
]

PE_FEATURE_NAMES = [
    "size_of_code_bytes",
    "major_linker_version",
    "entropy_score",
    "number_of_sections",
    "suspicious_imports_count",
    "is_digital_signed",
    "debug_data_size",
]
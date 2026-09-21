# ml/feature_extraction.py
"""
Feature extraction for AI Cyber Threat Detection System.

Two functions:
  - extract_url_features(url)  -> 10 numeric features from a URL
  - extract_pe_features(path)  -> 10 numeric features from a PE (EXE) file

No model training. No Flask. Just pure feature extraction.
"""

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
SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "account", "bank"]


# ------------------------------------------------------------------
# URL FEATURES  (10 features)
# ------------------------------------------------------------------
def extract_url_features(url: str) -> np.ndarray:
    """Return a 10-value numeric vector describing the given URL."""
    try:
        parsed = urlparse(url)

        # 1. total length
        # 2. number of dots
        # 3. number of hyphens
        # 4. number of digits
        # 5. number of special characters
        # 6. has https (1/0)
        # 7. uses IP address as host (1/0)
        # 8. number of subdomains
        # 9. number of suspicious keywords
        # 10. length of the domain
        features = [
            len(url),
            url.count("."),
            url.count("-"),
            sum(c.isdigit() for c in url),
            sum(not c.isalnum() for c in url),
            1 if parsed.scheme == "https" else 0,
            1 if _is_ip(parsed.netloc) else 0,
            parsed.netloc.count("."),
            sum(w in url.lower() for w in SUSPICIOUS_WORDS),
            len(parsed.netloc),
        ]
        return np.array(features, dtype=float)
    except Exception:
        return np.zeros(10, dtype=float)


def _is_ip(host: str) -> bool:
    """True if host looks like an IPv4 address."""
    host = host.split(":")[0]
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


# ------------------------------------------------------------------
# PE / EXE FEATURES  (10 features)
# ------------------------------------------------------------------
def extract_pe_features(file_path) -> np.ndarray:
    """
    Statically analyse a PE file (never execute it) and return
    10 numeric features. Returns zeros if the file is not a valid PE.
    """
    if not PEFILE_OK:
        return np.zeros(10, dtype=float)

    path = Path(file_path)
    if not path.exists():
        return np.zeros(10, dtype=float)

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()

        num_sections = pe.FILE_HEADER.NumberOfSections
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        size_of_code = pe.OPTIONAL_HEADER.SizeOfCode
        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
        subsystem = pe.OPTIONAL_HEADER.Subsystem

        # Number of imported functions
        imports = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports += len(entry.imports)

        # Average section entropy (unusually high = packed/malicious)
        entropies = [s.get_entropy() for s in pe.sections] or [0]
        avg_entropy = sum(entropies) / len(entropies)

        file_size = path.stat().st_size

        pe.close()

        return np.array(
            [
                num_sections,
                entry_point,
                image_base,
                size_of_code,
                size_of_image,
                subsystem,
                imports,
                avg_entropy,
                file_size,
                len(entropies),
            ],
            dtype=float,
        )
    except Exception:
        return np.zeros(10, dtype=float)


# Feature name lists (helpful for debugging / viva)
URL_FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_digits",
    "num_special", "has_https", "is_ip", "num_subdomains",
    "suspicious_words", "domain_length",
]

PE_FEATURE_NAMES = [
    "num_sections", "entry_point", "image_base", "size_of_code",
    "size_of_image", "subsystem", "num_imports", "avg_entropy",
    "file_size", "sections_count",
]
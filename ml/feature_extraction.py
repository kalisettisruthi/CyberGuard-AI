# ml/feature_extraction.py
"""
Feature Extraction Module for AI Cyber Threat Detection System

This module extracts features from URLs and PE files for machine learning.
"""

import re
import math
import numpy as np
from urllib.parse import urlparse
from pathlib import Path
from typing import Union

# Try to import pefile
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print("Warning: pefile not installed. EXE features will be limited.")


# ============================================================
# URL Feature Extraction
# ============================================================

def extract_url_features(url: str) -> np.ndarray:
    """
    Extract 13 features from a URL for phishing detection.
    
    Features:
    1. url_length          - Total URL length
    2. num_dots            - Number of dots
    3. num_hyphens         - Number of hyphens
    4. num_digits          - Number of digits
    5. num_special_chars   - Number of special characters
    6. has_https           - 1 if HTTPS, else 0
    7. is_ip_address       - 1 if IP address, else 0
    8. num_subdomains      - Number of subdomains
    9. has_at_symbol       - 1 if @ symbol present
    10. has_double_slash   - 1 if // appears in path
    11. is_shortened       - 1 if URL is shortened
    12. has_suspicious_keyword - 1 if suspicious keyword found
    13. has_login_keyword  - 1 if login-related keyword found
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()
        
        # Feature dictionary
        features = {
            'url_length': len(url),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_digits': sum(c.isdigit() for c in url),
            'num_special_chars': sum(not c.isalnum() for c in url),
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'is_ip_address': 1 if is_ip_address(domain) else 0,
            'num_subdomains': domain.count('.') if domain else 0,
            'has_at_symbol': 1 if '@' in url else 0,
            'has_double_slash': 1 if '//' in path else 0,
            'is_shortened': 1 if any(s in domain for s in ['bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl']) else 0,
            'has_suspicious_keyword': 1 if any(kw in full_url for kw in ['login', 'verify', 'secure', 'account', 'update']) else 0,
            'has_login_keyword': 1 if any(kw in full_url for kw in ['login', 'signin', 'logon', 'sign-in']) else 0
        }
        
        # Return as numpy array in consistent order
        feature_keys = [
            'url_length', 'num_dots', 'num_hyphens', 'num_digits', 'num_special_chars',
            'has_https', 'is_ip_address', 'num_subdomains',
            'has_at_symbol', 'has_double_slash', 'is_shortened',
            'has_suspicious_keyword', 'has_login_keyword'
        ]
        
        return np.array([features[k] for k in feature_keys], dtype=np.float32)
        
    except Exception:
        return np.zeros(13, dtype=np.float32)


def is_ip_address(domain: str) -> bool:
    """Check if domain is an IP address."""
    try:
        import ipaddress
        ipaddress.ip_address(domain.split(':')[0])
        return True
    except:
        return False


# ============================================================
# PE (Portable Executable) Feature Extraction
# ============================================================

def extract_pe_features(file_path: Union[str, Path]) -> np.ndarray:
    """
    Extract 14 features from a PE file for malware detection.
    
    Features:
    1. e_magic              - DOS header magic number
    2. e_lfanew             - Offset to NT header
    3. number_of_sections   - Number of sections
    4. address_of_entry_point - Entry point address
    5. image_base           - Preferred image base
    6. size_of_code         - Size of code section
    7. size_of_image        - Total image size
    8. size_of_headers      - Size of headers
    9. checksum             - File checksum
    10. subsystem           - Subsystem type
    11. dll_characteristics - DLL flags
    12. import_count        - Number of imported functions
    13. file_size           - Total file size in bytes
    """
    if not PEFILE_AVAILABLE:
        return np.zeros(14, dtype=np.float32)
    
    file_path = Path(file_path)
    
    if not file_path.exists():
        return np.zeros(14, dtype=np.float32)
    
    try:
        pe = pefile.PE(str(file_path))
        features = {}
        
        # DOS Header
        features['e_magic'] = pe.DOS_HEADER.e_magic
        features['e_lfanew'] = pe.DOS_HEADER.e_lfanew
        
        # File Header
        features['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
        
        # Optional Header
        if hasattr(pe, 'OPTIONAL_HEADER'):
            oh = pe.OPTIONAL_HEADER
            features['address_of_entry_point'] = oh.AddressOfEntryPoint
            features['image_base'] = oh.ImageBase
            features['size_of_code'] = oh.SizeOfCode
            features['size_of_image'] = oh.SizeOfImage
            features['size_of_headers'] = oh.SizeOfHeaders
            features['checksum'] = oh.CheckSum
            features['subsystem'] = oh.Subsystem
            features['dll_characteristics'] = oh.DllCharacteristics
        else:
            for key in ['address_of_entry_point', 'image_base', 'size_of_code', 
                       'size_of_image', 'size_of_headers', 'checksum', 
                       'subsystem', 'dll_characteristics']:
                features[key] = 0
        
        # Import count
        import_count = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                import_count += len(entry.imports)
        features['import_count'] = import_count
        
        # File size
        features['file_size'] = file_path.stat().st_size
        
        pe.close()
        
        # Return as numpy array
        feature_keys = [
            'e_magic', 'e_lfanew', 'number_of_sections',
            'address_of_entry_point', 'image_base', 'size_of_code',
            'size_of_image', 'size_of_headers', 'checksum',
            'subsystem', 'dll_characteristics',
            'import_count', 'file_size'
        ]
        
        return np.array([features.get(k, 0) for k in feature_keys], dtype=np.float32)
        
    except Exception:
        return np.zeros(14, dtype=np.float32)


# ============================================================
# Helper Functions
# ============================================================

def get_url_feature_names():
    """Return list of URL feature names."""
    return [
        'url_length', 'num_dots', 'num_hyphens', 'num_digits', 'num_special_chars',
        'has_https', 'is_ip_address', 'num_subdomains',
        'has_at_symbol', 'has_double_slash', 'is_shortened',
        'has_suspicious_keyword', 'has_login_keyword'
    ]


def get_pe_feature_names():
    """Return list of PE feature names."""
    return [
        'e_magic', 'e_lfanew', 'number_of_sections',
        'address_of_entry_point', 'image_base', 'size_of_code',
        'size_of_image', 'size_of_headers', 'checksum',
        'subsystem', 'dll_characteristics',
        'import_count', 'file_size'
    ]
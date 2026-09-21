# config.py
"""
Configuration for AI Cyber Threat Detection System.

Holds folder paths, upload limits, and model file locations.
"""

import os
from pathlib import Path

# Project root folder
BASE_DIR = Path(__file__).parent

# Flask
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
DEBUG = True

# Upload settings
UPLOAD_FOLDER = BASE_DIR / "uploads"
MAX_CONTENT_LENGTH = 100 * 1024 * 1024   # 100 MB
ALLOWED_EXTENSIONS = {"exe"}

# Model paths
MODEL_FOLDER = BASE_DIR / "ml" / "models"
WEBSITE_MODEL_PATH = MODEL_FOLDER / "website_model.joblib"
MALWARE_MODEL_PATH = MODEL_FOLDER / "malware_model.joblib"

# Dataset paths
PHISHING_DATASET = BASE_DIR / "datasets" / "phishing_dataset.csv"
MALWARE_DATASET = BASE_DIR / "datasets" / "malware_dataset.csv"

# Create required folders if they don't exist
UPLOAD_FOLDER.mkdir(exist_ok=True)
MODEL_FOLDER.mkdir(parents=True, exist_ok=True)
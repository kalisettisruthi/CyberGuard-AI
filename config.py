# config.py
"""
Configuration file for AI Cyber Threat Detection System

This file contains all configuration variables used by the Flask application.
"""

import os
from pathlib import Path

# Base directory - root of the project
BASE_DIR = Path(__file__).parent

# ============================================================
# Flask Configuration
# ============================================================

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
DEBUG = os.environ.get('FLASK_ENV', 'development') == 'development'

# ============================================================
# File Upload Configuration
# ============================================================

UPLOAD_FOLDER = BASE_DIR / 'uploads'
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {'exe'}

# ============================================================
# Model Configuration
# ============================================================

MODEL_FOLDER = BASE_DIR / 'ml' / 'models'
WEBSITE_MODEL_PATH = MODEL_FOLDER / 'website_model.joblib'
WEBSITE_SCALER_PATH = MODEL_FOLDER / 'website_scaler.joblib'
MALWARE_MODEL_PATH = MODEL_FOLDER / 'malware_model.joblib'
MALWARE_SCALER_PATH = MODEL_FOLDER / 'malware_scaler.joblib'

# ============================================================
# Create Required Directories
# ============================================================

UPLOAD_FOLDER.mkdir(exist_ok=True)
MODEL_FOLDER.mkdir(parents=True, exist_ok=True)
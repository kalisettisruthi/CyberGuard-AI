# app.py
"""
AI Cyber Threat Detection System - Flask Application

This is the main entry point for the web application.
It handles routes, file uploads, and predictions.
"""

import os
import hashlib
import logging
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

# Import configuration
from config import (
    SECRET_KEY, DEBUG, UPLOAD_FOLDER, MAX_CONTENT_LENGTH,
    ALLOWED_EXTENSIONS, WEBSITE_MODEL_PATH, WEBSITE_SCALER_PATH,
    MALWARE_MODEL_PATH, MALWARE_SCALER_PATH
)

# Import feature extraction
from ml.feature_extraction import extract_url_features, extract_pe_features

# ============================================================
# Initialize Flask App
# ============================================================

app = Flask(__name__, template_folder='templates', static_folder='static')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['DEBUG'] = DEBUG
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================
# Load ML Models (Lazy Loading)
# ============================================================

website_model = None
website_scaler = None
malware_model = None
malware_scaler = None

def load_website_model():
    """Load website detection model and scaler."""
    global website_model, website_scaler
    if website_model is None:
        try:
            import joblib
            website_model = joblib.load(WEBSITE_MODEL_PATH)
            website_scaler = joblib.load(WEBSITE_SCALER_PATH)
            logger.info("✅ Website model loaded successfully")
        except Exception as e:
            logger.error(f"❌ Failed to load website model: {e}")
            website_model = None
            website_scaler = None
    return website_model, website_scaler

def load_malware_model():
    """Load malware detection model and scaler."""
    global malware_model, malware_scaler
    if malware_model is None:
        try:
            import joblib
            malware_model = joblib.load(MALWARE_MODEL_PATH)
            malware_scaler = joblib.load(MALWARE_SCALER_PATH)
            logger.info("✅ Malware model loaded successfully")
        except Exception as e:
            logger.error(f"❌ Failed to load malware model: {e}")
            malware_model = None
            malware_scaler = None
    return malware_model, malware_scaler

# ============================================================
# Helper Functions
# ============================================================

def allowed_file(filename):
    """Check if uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_risk_level(prediction, confidence):
    """Determine risk level based on prediction and confidence."""
    if prediction == 1:  # Threat detected
        if confidence > 80:
            return 'High'
        elif confidence > 60:
            return 'Medium'
        else:
            return 'Low'
    else:  # Safe
        return 'Low'

def get_recommendations(prediction, risk_level):
    """Generate recommendations based on prediction and risk level."""
    if prediction == 1:  # Threat detected
        if risk_level == 'High':
            return [
                '⚠️ High-risk threat detected. Do not proceed.',
                'Report this to your security team immediately.',
                'Block this URL/file in your security systems.'
            ]
        elif risk_level == 'Medium':
            return [
                '⚠️ Medium-risk threat detected.',
                'Exercise caution and analyze further.',
                'Consider isolating the affected system.'
            ]
        else:
            return [
                '⚠️ Low-confidence threat detection.',
                'Consider running additional scans.',
                'Monitor for suspicious activity.'
            ]
    else:  # Safe
        return [
            '✅ No threat detected. Continue with normal operations.',
            'Regular monitoring is recommended.',
            'Keep your security software updated.'
        ]

# ============================================================
# Frontend Routes
# ============================================================

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/website')
def website_detection():
    """Website detection page."""
    return render_template('website.html')

@app.route('/exe')
def exe_detection():
    """EXE detection page."""
    return render_template('exe.html')

@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')

# ============================================================
# API Routes
# ============================================================

@app.route('/predict-url', methods=['POST'])
def predict_url():
    """
    Predict if a URL is malicious.
    
    Expects JSON: {"url": "https://example.com"}
    Returns: Prediction, confidence, risk level, recommendations
    """
    try:
        # Get and validate URL
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        logger.info(f"Predicting URL: {url}")
        
        # Load model
        model, scaler = load_website_model()
        if model is None:
            return jsonify({'error': 'Model not loaded. Please train the model first.'}), 503
        
        # Extract features
        features = extract_url_features(url).reshape(1, -1)
        
        # Scale features
        features_scaled = scaler.transform(features)
        
        # Predict
        prediction = model.predict(features_scaled)[0]  # 0=safe, 1=malicious
        confidence = model.predict_proba(features_scaled)[0].max() * 100
        
        # Generate response
        risk = get_risk_level(prediction, confidence)
        recommendations = get_recommendations(prediction, risk)
        
        response = {
            'prediction': 'Threat Detected' if prediction == 1 else 'Safe',
            'confidence': round(confidence, 2),
            'risk_level': risk,
            'recommendations': recommendations
        }
        
        logger.info(f"URL prediction: {response['prediction']}")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in predict_url: {e}")
        return jsonify({'error': 'Failed to process URL'}), 500

@app.route('/predict-exe', methods=['POST'])
def predict_exe():
    """
    Predict if an EXE file is malicious.
    
    Expects: Multipart form with 'file' field
    Returns: Prediction, confidence, risk level, SHA256, filename, filesize
    """
    file_path = None
    
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({'error': 'Only .exe files are allowed'}), 400
        
        # Save file securely
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_filename = f"{timestamp}_{filename}"
        file_path = UPLOAD_FOLDER / safe_filename
        file.save(str(file_path))
        
        logger.info(f"File saved: {safe_filename}")
        
        # Calculate SHA256 and file size
        sha256_hash = calculate_sha256(file_path)
        file_size = f"{file_path.stat().st_size / (1024 * 1024):.2f} MB"
        
        # Load model
        model, scaler = load_malware_model()
        if model is None:
            return jsonify({'error': 'Model not loaded. Please train the model first.'}), 503
        
        # Extract features
        features = extract_pe_features(file_path).reshape(1, -1)
        
        # Scale features
        features_scaled = scaler.transform(features)
        
        # Predict
        prediction = model.predict(features_scaled)[0]  # 0=safe, 1=malware
        confidence = model.predict_proba(features_scaled)[0].max() * 100
        
        # Generate response
        risk = get_risk_level(prediction, confidence)
        recommendations = get_recommendations(prediction, risk)
        
        response = {
            'filename': filename,
            'filesize': file_size,
            'sha256': sha256_hash,
            'prediction': 'Malware Detected' if prediction == 1 else 'Safe',
            'confidence': round(confidence, 2),
            'risk_level': risk,
            'recommendations': recommendations
        }
        
        logger.info(f"EXE prediction: {response['prediction']}")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in predict_exe: {e}")
        return jsonify({'error': 'Failed to analyze EXE file'}), 500
        
    finally:
        # Cleanup: Delete temporary file
        if file_path and file_path.exists():
            try:
                file_path.unlink()
                logger.info(f"Temporary file deleted: {file_path}")
            except Exception as e:
                logger.error(f"Failed to delete temp file: {e}")

# ============================================================
# Health Check Route
# ============================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'models_loaded': website_model is not None or malware_model is not None
    }), 200

# ============================================================
# Run Application
# ============================================================

if __name__ == '__main__':
    logger.info("=" * 50)
    logger.info("AI Cyber Threat Detection System")
    logger.info("=" * 50)
    logger.info(f"Upload folder: {UPLOAD_FOLDER}")
    logger.info(f"Max file size: {MAX_CONTENT_LENGTH / (1024 * 1024):.0f} MB")
    logger.info(f"Models folder: {WEBSITE_MODEL_PATH.parent}")
    logger.info("=" * 50)
    
    app.run(host='0.0.0.0', port=5000, debug=DEBUG)
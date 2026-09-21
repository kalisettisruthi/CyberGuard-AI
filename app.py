# app.py
"""
AI Cyber Threat Detection System — Flask Application.

Handles:
  - Page routes (index, website, exe, about)
  - POST /predict-url  -> website threat prediction
  - POST /predict-exe  -> EXE malware prediction

Models are loaded once at startup from ml/models/.
"""

import hashlib
from datetime import datetime
from pathlib import Path

import joblib
from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

import config
from ml.feature_extraction import extract_url_features, extract_pe_features

# ---------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["UPLOAD_FOLDER"] = str(config.UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH

# ---------------------------------------------------------------
# Load models ONCE at startup
# ---------------------------------------------------------------
website_model = joblib.load(config.WEBSITE_MODEL_PATH)
malware_model = joblib.load(config.MALWARE_MODEL_PATH)
print("✅ Models loaded.")


# ---------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------
def _risk_level(pred: int, conf: float) -> str:
    """Map prediction + confidence to Low / Medium / High."""
    if pred == 0:
        return "Low"
    if conf >= 80:
        return "High"
    if conf >= 60:
        return "Medium"
    return "Low"


def _recommendation(pred: int, risk: str) -> str:
    """Simple human-readable recommendation."""
    if pred == 0:
        return "No threat detected. Safe to proceed."
    if risk == "High":
        return "High-risk threat detected. Do NOT proceed."
    return "Suspicious content detected. Proceed with caution."


def _allowed_file(name: str) -> bool:
    return "." in name and name.rsplit(".", 1)[1].lower() in config.ALLOWED_EXTENSIONS


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/website")
def website():
    return render_template("website.html")


@app.route("/exe")
def exe():
    return render_template("exe.html")


@app.route("/about")
def about():
    return render_template("about.html")


# ---------------------------------------------------------------
# API: Website prediction
# ---------------------------------------------------------------
@app.route("/predict-url", methods=["POST"])
def predict_url():
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "URL is required"}), 400

        feats = extract_url_features(url).reshape(1, -1)
        pred = int(website_model.predict(feats)[0])
        conf = float(website_model.predict_proba(feats)[0].max() * 100)

        risk = _risk_level(pred, conf)
        return jsonify({
            "prediction": "Malicious" if pred == 1 else "Safe",
            "confidence": round(conf, 2),
            "risk_level": risk,
            "recommendation": _recommendation(pred, risk),
        }), 200

    except Exception as e:
        print("predict_url error:", e)
        return jsonify({"error": "Failed to analyze URL"}), 500


# ---------------------------------------------------------------
# API: EXE prediction
# ---------------------------------------------------------------
@app.route("/predict-exe", methods=["POST"])
def predict_exe():
    tmp_path = None
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400
        if not _allowed_file(file.filename):
            return jsonify({"error": "Only .exe files are allowed"}), 400

        # Save temporarily with a unique, safe name
        safe_name = secure_filename(file.filename)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        tmp_path = Path(config.UPLOAD_FOLDER) / f"{stamp}_{safe_name}"
        file.save(tmp_path)

        # Hash + size
        file_hash = _sha256(tmp_path)
        file_size = f"{tmp_path.stat().st_size / (1024 * 1024):.2f} MB"

        # Features + prediction
        feats = extract_pe_features(tmp_path).reshape(1, -1)
        if feats.sum() == 0:
            return jsonify({"error": "File is not a valid PE (.exe)"}), 400

        pred = int(malware_model.predict(feats)[0])
        conf = float(malware_model.predict_proba(feats)[0].max() * 100)

        risk = _risk_level(pred, conf)
        return jsonify({
            "filename": safe_name,
            "filesize": file_size,
            "sha256": file_hash,
            "prediction": "Malicious" if pred == 1 else "Safe",
            "confidence": round(conf, 2),
            "risk_level": risk,
            "recommendation": _recommendation(pred, risk),
        }), 200

    except Exception as e:
        print("predict_exe error:", e)
        return jsonify({"error": "Failed to analyze file"}), 500

    finally:
        # Always delete the temporary upload
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


# ---------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=config.DEBUG)
# ml/website_model.py
"""
Website Threat Detection - Model Training Script

This script trains a Random Forest classifier to detect malicious websites.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path
import sys

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
from ml.feature_extraction import extract_url_features

# ============================================================
# Configuration
# ============================================================

# Paths - UPDATE THESE BASED ON YOUR DATASET
DATASET_PATH = Path(__file__).parent.parent / 'datasets' / 'phishing_dataset.csv'
MODEL_PATH = Path(__file__).parent / 'models' / 'website_model.joblib'
SCALER_PATH = Path(__file__).parent / 'models' / 'website_scaler.joblib'

# Column names - UPDATE THESE BASED ON YOUR DATASET
URL_COLUMN = 'url'      # Column containing URLs
LABEL_COLUMN = 'label'  # Column containing labels (0=safe, 1=malicious)

# Model parameters
N_ESTIMATORS = 100
TEST_SIZE = 0.2
RANDOM_STATE = 42


# ============================================================
# Training Function
# ============================================================

def train_website_model():
    """Train Random Forest model for website detection."""
    
    print("=" * 60)
    print("WEBSITE THREAT DETECTION - MODEL TRAINING")
    print("=" * 60)
    
    # ============================================================
    # Step 1: Load Dataset
    # ============================================================
    print("\n[1] Loading dataset...")
    
    if not DATASET_PATH.exists():
        print(f"❌ Dataset not found: {DATASET_PATH}")
        print("Please place your dataset at this location.")
        print("Expected format: CSV with 'url' and 'label' columns")
        return None
    
    df = pd.read_csv(DATASET_PATH)
    print(f"✅ Dataset loaded: {len(df)} samples")
    print(f"   Columns: {df.columns.tolist()}")
    
    # Check label distribution
    if LABEL_COLUMN in df.columns:
        counts = df[LABEL_COLUMN].value_counts()
        print(f"   Labels: Safe={counts.get(0, 0)}, Malicious={counts.get(1, 0)}")
    
    # ============================================================
    # Step 2: Extract Features
    # ============================================================
    print("\n[2] Extracting features from URLs...")
    
    features = []
    labels = []
    
    for idx, row in df.iterrows():
        try:
            url = row[URL_COLUMN]
            label = row[LABEL_COLUMN]
            
            feature_vector = extract_url_features(url)
            features.append(feature_vector)
            labels.append(label)
            
            if (idx + 1) % 1000 == 0:
                print(f"   Processed {idx + 1} URLs...")
                
        except Exception as e:
            print(f"   Warning: Failed to process URL: {url[:50]}...")
            continue
    
    X = np.array(features)
    y = np.array(labels)
    
    print(f"✅ Feature extraction complete")
    print(f"   Feature shape: {X.shape}")
    
    # ============================================================
    # Step 3: Split Data
    # ============================================================
    print("\n[3] Splitting data into train/test sets...")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    
    print(f"   Training: {len(X_train)} samples")
    print(f"   Testing: {len(X_test)} samples")
    
    # ============================================================
    # Step 4: Scale Features
    # ============================================================
    print("\n[4] Scaling features...")
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("✅ Feature scaling complete")
    
    # ============================================================
    # Step 5: Train Model
    # ============================================================
    print("\n[5] Training Random Forest model...")
    
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )
    
    model.fit(X_train_scaled, y_train)
    print("✅ Model training complete")
    
    # ============================================================
    # Step 6: Evaluate Model
    # ============================================================
    print("\n[6] Evaluating model...")
    
    y_pred = model.predict(X_test_scaled)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    print(f"\n   📊 Results:")
    print(f"   {'=' * 40}")
    print(f"   Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"   Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"   Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"   F1 Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"\n   Confusion Matrix:")
    print(f"   [[{cm[0][0]:4d} {cm[0][1]:4d}]")
    print(f"    [{cm[1][0]:4d} {cm[1][1]:4d}]]")
    print(f"   {'=' * 40}")
    
    # ============================================================
    # Step 7: Save Model
    # ============================================================
    print("\n[7] Saving model...")
    
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    joblib.dump(model, MODEL_PATH)
    print(f"✅ Model saved: {MODEL_PATH}")
    
    joblib.dump(scaler, SCALER_PATH)
    print(f"✅ Scaler saved: {SCALER_PATH}")
    
    print("\n" + "=" * 60)
    print("✅ WEBSITE MODEL TRAINING COMPLETE")
    print("=" * 60)
    
    return model, scaler


# ============================================================
# Create Sample Dataset (If No Dataset Exists)
# ============================================================

def create_sample_dataset():
    """Create a sample dataset for testing."""
    
    print("\nCreating sample dataset...")
    
    sample_data = [
        # Safe URLs (label=0)
        ("https://google.com", 0),
        ("https://github.com", 0),
        ("https://stackoverflow.com", 0),
        ("https://python.org", 0),
        ("https://wikipedia.org", 0),
        ("https://youtube.com", 0),
        ("https://reddit.com", 0),
        ("https://amazon.com", 0),
        ("https://netflix.com", 0),
        ("https://spotify.com", 0),
        
        # Malicious URLs (label=1)
        ("http://malicious-site.xyz/login", 1),
        ("http://phishing-site.top/verify", 1),
        ("https://secure-banking.xyz/update", 1),
        ("http://login-verification.space", 1),
        ("https://account-verify.work", 1),
        ("http://bit.ly/phishing-link", 1),
        ("https://tinyurl.com/malicious", 1),
        ("http://192.168.1.1/admin", 1),
        ("https://fake-paypal.com/signin", 1),
        ("http://verify-account.xyz", 1),
    ]
    
    df = pd.DataFrame(sample_data, columns=['url', 'label'])
    
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)
    
    print(f"✅ Sample dataset created: {DATASET_PATH}")
    print(f"   {len(df)} samples (Safe: {len(df[df['label']==0])}, Malicious: {len(df[df['label']==1])})")


# ============================================================
# Main Execution
# ============================================================

if __name__ == "__main__":
    # Check if dataset exists
    if not DATASET_PATH.exists():
        print(f"\nDataset not found: {DATASET_PATH}")
        create = input("Create a sample dataset for testing? (y/n): ")
        if create.lower() == 'y':
            create_sample_dataset()
        else:
            print("\nPlease place your dataset at:")
            print(f"  {DATASET_PATH}")
            print("Expected format: CSV with 'url' and 'label' columns")
            print("  - url: The website URL")
            print("  - label: 0 for safe, 1 for malicious")
            sys.exit(0)
    
    # Train the model
    train_website_model()
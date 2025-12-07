#!/usr/bin/env python3
"""
Training script for Kaggle datasets
Handles CSV files with URL and label columns
"""

import sys
import os
import pandas as pd
import zipfile

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishsense.train_model import train_model, load_from_file, prepare_features, feature_extractor_to_vector
from phishsense.feature_extractor import FeatureExtractor
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pickle


def load_kaggle_csv(zip_path, url_column='url', label_column='label'):
    """
    Load Kaggle dataset from ZIP file containing CSV
    
    Args:
        zip_path: Path to ZIP file
        url_column: Name of column containing URLs (default: 'url')
        label_column: Name of column containing labels (default: 'label')
                    Labels should be: 1 or 'phishing' for phishing, 0 or 'legitimate' for safe
    
    Returns:
        tuple: (urls_list, labels_list)
    """
    urls = []
    labels = []
    
    if not os.path.exists(zip_path):
        print(f"Error: File not found: {zip_path}")
        return urls, labels
    
    print(f"Loading Kaggle dataset from: {zip_path}")
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Find CSV files
            csv_files = [f for f in zip_ref.namelist() if f.endswith('.csv')]
            
            if not csv_files:
                print("Error: No CSV files found in ZIP")
                return urls, labels
            
            print(f"Found CSV files: {csv_files}")
            
            # Read first CSV file (or you can specify which one)
            csv_file = csv_files[0]
            print(f"Reading: {csv_file}")
            
            with zip_ref.open(csv_file) as f:
                # Read CSV
                df = pd.read_csv(f)
                
                print(f"Dataset shape: {df.shape}")
                print(f"Columns: {df.columns.tolist()}")
                
                # Try to find URL column (case insensitive)
                url_col = None
                for col in df.columns:
                    if col.lower() in ['url', 'link', 'website', 'domain']:
                        url_col = col
                        break
                
                if url_col is None:
                    print("Available columns:", df.columns.tolist())
                    url_col = input(f"Enter URL column name (or press Enter for '{url_column}'): ").strip()
                    if not url_col:
                        url_col = url_column
                
                # Try to find label column
                label_col = None
                for col in df.columns:
                    if col.lower() in ['label', 'type', 'class', 'phishing', 'result', 'status']:
                        label_col = col
                        break
                
                if label_col is None:
                    print("Available columns:", df.columns.tolist())
                    label_col = input(f"Enter label column name (or press Enter for '{label_column}'): ").strip()
                    if not label_col:
                        label_col = label_column
                
                if url_col not in df.columns:
                    print(f"Error: Column '{url_col}' not found")
                    return urls, labels
                
                if label_col not in df.columns:
                    print(f"Error: Column '{label_col}' not found")
                    return urls, labels
                
                # Extract URLs and labels
                for idx, row in df.iterrows():
                    url = str(row[url_col]).strip()
                    label = row[label_col]
                    
                    # Skip empty URLs
                    if not url or url.lower() in ['nan', 'none', '']:
                        continue
                    
                    # Normalize label
                    if isinstance(label, str):
                        label_lower = label.lower()
                        if 'phish' in label_lower or label_lower == '1' or label_lower == 'malicious':
                            label_value = 1
                        elif 'legit' in label_lower or label_lower == '0' or label_lower == 'benign' or label_lower == 'safe':
                            label_value = 0
                        else:
                            continue  # Skip unknown labels
                    else:
                        # Numeric label
                        label_value = int(label)
                    
                    urls.append(url)
                    labels.append(label_value)
                
                print(f"\nLoaded {len(urls)} URLs")
                print(f"  Phishing: {sum(labels)}")
                print(f"  Legitimate: {len(labels) - sum(labels)}")
                
    except Exception as e:
        print(f"Error loading Kaggle dataset: {e}")
        import traceback
        traceback.print_exc()
        return urls, labels
    
    return urls, labels


def train_from_kaggle(zip_path, model_output='phishsense/models/phishing_model.pkl'):
    """Train model from Kaggle ZIP dataset"""
    
    # Load dataset
    urls, labels = load_kaggle_csv(zip_path)
    
    if len(urls) == 0:
        print("Error: No URLs loaded from dataset")
        return
    
    if len(set(labels)) < 2:
        print("Error: Dataset must contain both phishing and legitimate URLs")
        return
    
    # Extract features
    feature_extractor = FeatureExtractor()
    print("\nExtracting features from URLs...")
    
    features_list = []
    labels_list = []
    
    for i, url in enumerate(urls):
        if i % 100 == 0 and i > 0:
            print(f"Processed {i}/{len(urls)} URLs...")
        
        try:
            features = feature_extractor.extract_features(url)
            feature_vector = feature_extractor_to_vector(features)
            features_list.append(feature_vector)
            labels_list.append(labels[i])
        except Exception as e:
            if i < 10:  # Show first few errors
                print(f"Warning: Error processing URL {url[:50]}...: {e}")
            continue
    
    if len(features_list) == 0:
        print("Error: No features extracted")
        return
    
    X = np.array(features_list)
    y = np.array(labels_list)
    
    print(f"\nExtracted features from {len(X)} URLs")
    print(f"Feature vector shape: {X.shape}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Train model
    print("\nTraining Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=200,  # Increased for better accuracy
        max_depth=25,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\nEvaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n{'='*60}")
    print(f"Model Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"{'='*60}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print(f"  True Negatives (Safe correctly identified): {cm[0][0]}")
    print(f"  False Positives (Safe misidentified as phishing): {cm[0][1]}")
    print(f"  False Negatives (Phishing misidentified as safe): {cm[1][0]}")
    print(f"  True Positives (Phishing correctly identified): {cm[1][1]}")
    
    # Save model
    os.makedirs(os.path.dirname(model_output), exist_ok=True)
    with open(model_output, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"\n✅ Model saved to {model_output}")
    print("\nYou can now use the trained model with:")
    print("  python phishsense_cli.py <url>")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Train PhishSense model from Kaggle dataset')
    parser.add_argument('dataset', help='Path to Kaggle ZIP dataset file')
    parser.add_argument('--output', default='phishsense/models/phishing_model.pkl',
                       help='Output path for trained model')
    
    args = parser.parse_args()
    
    train_from_kaggle(args.dataset, args.output)


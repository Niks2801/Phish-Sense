"""
Training Script for PhishSense ML Model
Trains a machine learning model on phishing and legitimate URLs
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pickle
import os
import zipfile
from .feature_extractor import FeatureExtractor


def load_from_file(file_path):
    """Load URLs from a file (supports .txt and .zip)"""
    urls = []
    
    if not os.path.exists(file_path):
        return urls
    
    # Check if it's a ZIP file
    if file_path.endswith('.zip'):
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref: 
                # Get list of files in ZIP
                file_list = zip_ref.namelist()
                
                # Try to find text files in ZIP
                text_files = [f for f in file_list if f.endswith('.txt') or f.endswith('.csv')]
                
                if not text_files:
                    # If no .txt files, try reading all files
                    text_files = file_list
                
                # Read from first text file found (or all if multiple)
                for text_file in text_files:
                    try:
                        with zip_ref.open(text_file) as f:
                            # Try different encodings
                            for encoding in ['utf-8', 'latin-1', 'iso-8859-1']:
                                try:
                                    content = f.read().decode(encoding)
                                    lines = content.split('\n')
                                    urls.extend([line.strip() for line in lines if line.strip()])
                                    break
                                except UnicodeDecodeError:
                                    continue
                    except Exception as e:
                        print(f"Warning: Could not read {text_file} from ZIP: {e}")
                        continue
        except Exception as e:
            print(f"Error reading ZIP file {file_path}: {e}")
            return urls
    else:
        # Regular text file
        try:
            # Try different encodings
            for encoding in ['utf-8', 'latin-1', 'iso-8859-1']: 
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        urls = [line.strip() for line in f if line.strip()]
                        break
                except UnicodeDecodeError:
                    continue
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
    
    return urls


def load_dataset(phishing_file, legitimate_file):
    """Load datasets from files (supports .txt and .zip)"""
    phishing_urls = []
    legitimate_urls = []
    
    print(f"Loading phishing dataset from: {phishing_file}")
    phishing_urls = load_from_file(phishing_file)
    
    print(f"Loading legitimate dataset from: {legitimate_file}")
    legitimate_urls = load_from_file(legitimate_file)
    
    return phishing_urls, legitimate_urls


def prepare_features(urls, labels, feature_extractor):
    """Extract features from URLs"""
    features_list = []
    labels_list = []
    
    print("Extracting features...")
    for i, url in enumerate(urls):
        if i % 100 == 0:
            print(f"Processed {i}/{len(urls)} URLs...")
        
        try:
            features = feature_extractor.extract_features(url)
            feature_vector = feature_extractor_to_vector(features)
            features_list.append(feature_vector)
            labels_list.append(labels[i])
        except Exception as e:
            print(f"Error processing {url}: {e}")
            continue
    
    return np.array(features_list), np.array(labels_list)


def feature_extractor_to_vector(features):
    """Convert features dict to vector"""
    feature_order = [
        'url_length', 'hostname_length', 'path_length', 'query_length',
        'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
        'num_question_marks', 'num_equals', 'num_ampersands', 'num_percent',
        'num_at_symbols', 'has_https', 'has_http', 'domain_in_subdomain',
        'has_ip', 'is_shortened', 'suspicious_tld', 'suspicious_keywords',
        'has_port', 'num_params', 'has_redirect', 'domain_age',
        'has_valid_ssl', 'dns_record_count', 'is_typosquatting',
        'dots_to_length', 'hyphens_to_length'
    ]
    
    vector = []
    for feature in feature_order:
        vector.append(features.get(feature, 0))
    
    return vector


def train_model(phishing_file='data/phishing_urls.txt', 
                legitimate_file='data/legitimate_urls.txt',
                model_output='phishsense/models/phishing_model.pkl'):
    """Train the phishing detection model"""
    
    print("Loading datasets...")
    phishing_urls, legitimate_urls = load_dataset(phishing_file, legitimate_file)
    
    if not phishing_urls or not legitimate_urls:
        print("Error: Dataset files not found or empty")
        print("Please provide:")
        print("  - data/phishing_urls.txt (or .zip)")
        print("  - data/legitimate_urls.txt (or .zip)")
        print("\nSupported formats:")
        print("  - Plain text files (.txt) - one URL per line")
        print("  - ZIP files (.zip) - containing .txt or .csv files")
        return
    
    print(f"Loaded {len(phishing_urls)} phishing URLs")
    print(f"Loaded {len(legitimate_urls)} legitimate URLs")
    
    # Combine and label
    all_urls = phishing_urls + legitimate_urls
    all_labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
    
    # Extract features
    feature_extractor = FeatureExtractor() 
    X, y = prepare_features(all_urls, all_labels, feature_extractor)
    
    if len(X) == 0:
        print("Error: No features extracted")
        return
    
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
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    print("\nEvaluating model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nAccuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Save model
    os.makedirs(os.path.dirname(model_output), exist_ok=True)
    with open(model_output, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"\nModel saved to {model_output}")


if __name__ == '__main__':
    train_model()


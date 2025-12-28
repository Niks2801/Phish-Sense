#  PhishSense - Advanced Phishing URL Detection System (CLI)

PhishSense is a comprehensive cybersecurity tool that detects phishing URLs using a combination of machine learning algorithms and heuristic analysis. It analyzes multiple features of URLs to identify potential phishing attempts with high accuracy.

## Features

- **Dual Detection System**: Combines ML-based classification with heuristic rule-based detection
- **Feature Analysis**: Extracts and analyzes different URL features including:
  - URL structure and length analysis
  - Domain age and SSL certificate validation
  - Suspicious keyword detection
  - Typosquatting pattern recognition
  - Shortened URL detection
  - And many more...
- **Command-Line Interface**: Fast, lightweight CLI tool
- **Threat Level Classification**: Categorizes URLs as SAFE, LOW, MEDIUM, HIGH, or CRITICAL
- **Detailed Reporting**: Provides specific reasons for phishing detection
- **JSON Output**: Supports JSON output for scripting and automation

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [License](#license)

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Step 1: Clone the Repository

```bash
git clone https://github.com/niks2801/PhishSense.git
cd PhishSense
```

### Step 2: Install Dependencies

**Option A: Using Installation Script (Recommended)**

```bash
chmod +x install_cli.sh
./install_cli.sh
```

**Option B: Manual Installation**

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements_cli.txt
```

### Step 3: (Optional) Train the ML Model

If you want to train your own model with custom data:

```bash
python -m phishsense.train_model
```

This will use the sample datasets in `data/` directory. You can replace them with your own datasets.

**Supported formats:**
- Plain text files (`.txt`) - one URL per line
- ZIP files (`.zip`) - containing text files (great for large datasets)

See [DATASET_GUIDE.md](DATASET_GUIDE.md) for detailed information on using ZIP datasets.

##  Usage

### Command Line Interface

Check a single URL:

```bash
# Activate virtual environment first
source venv/bin/activate

# Basic check
python phishsense_cli.py https://example.com

# With verbose output
python phishsense_cli.py https://example.com --verbose

# JSON output for scripting
python phishsense_cli.py https://example.com --json
```

### Python API

```python
from phishsense.detector import PhishDetector

# Initialize detector
detector = PhishDetector()

# Check a URL
result = detector.detect("https://example.com")

print(f"Is Phishing: {result['is_phishing']}")
print(f"Confidence: {result['confidence']}")
print(f"Threat Level: {result['threat_level']}")
print(f"Reasons: {result['reasons']}")
```

## How It Works

### Detection Pipeline

1. **Feature Extraction**: The system extracts 29 features from the URL:
   - Structural features (length, character counts)
   - Domain features (age, SSL, DNS records)
   - Security features (HTTPS, certificate validity)
   - Behavioral features (suspicious keywords, patterns)

2. **Heuristic Analysis**: Applies rule-based detection:
   - Checks for suspicious TLDs (.tk, .ml, .ga, etc.)
   - Detects IP addresses in domain
   - Identifies shortened URLs
   - Analyzes domain age
   - Validates SSL certificates
   - Detects typosquatting patterns

3. **Machine Learning Classification**: Uses Random Forest classifier:
   - Trained on labeled datasets
   - Provides probability scores
   - Handles complex patterns

4. **Score Combination**: Merges heuristic and ML scores:
   - Weighted combination based on ML confidence
   - Final score between 0.0 (safe) and 1.0 (phishing)

5. **Threat Classification**: Categorizes based on final score:
   - SAFE: 0.0 - 0.2
   - LOW: 0.2 - 0.4
   - MEDIUM: 0.4 - 0.6
   - HIGH: 0.6 - 0.8
   - CRITICAL: 0.8 - 1.0

### Key Features Analyzed

| Feature Category | Examples |
|-----------------|----------|
| **URL Structure** | Length, path depth, query parameters |
| **Domain Analysis** | Age, TLD, subdomain patterns |
| **Security** | HTTPS, SSL certificate validity |
| **Patterns** | Suspicious keywords, typosquatting |
| **Network** | DNS records, IP addresses |
| **Behavior** | Shortened URLs, redirects |

## Project Structure

```
PhishSense/
├── phishsense_cli.py          # Main CLI script (run this!)
├── phishsense/
│   ├── __init__.py
│   ├── detector.py             # Main detection engine
│   ├── feature_extractor.py    # Feature extraction logic
│   ├── train_model.py          # ML model training script
│   └── models/
│       └── phishing_model.pkl  # Trained ML model
├── data/
│   ├── phishing_urls.txt       # Sample phishing URLs
│   └── legitimate_urls.txt     # Sample legitimate URLs
├── requirements_cli.txt        # Python dependencies
├── install_cli.sh              # Installation script
└── README.md                    # This file
# Phish-Sense

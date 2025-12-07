# 📊 Training with Kaggle Dataset

## 📍 Where to Place Your Dataset

Place your Kaggle ZIP dataset in the `data/` directory:

```
PhishSense/
└── data/
    └── kaggle_dataset.zip    ← Put your Kaggle ZIP here
```

## 🚀 Quick Start

### Step 1: Place Your Dataset

```bash
# Copy your Kaggle ZIP file to data directory
cp /path/to/your/kaggle_dataset.zip data/kaggle_dataset.zip
```

### Step 2: Train the Model

```bash
# Activate virtual environment
source venv/bin/activate

# Train with Kaggle dataset
python train_kaggle.py data/kaggle_dataset.zip
```

## 📋 Supported Kaggle Dataset Formats

The script automatically detects:
- **CSV files** inside ZIP
- **URL column** (looks for: url, link, website, domain)
- **Label column** (looks for: label, type, class, phishing, result, status)

### Label Formats Supported:
- **Numeric**: `1` = phishing, `0` = legitimate
- **Text**: `phishing`, `malicious` = phishing | `legitimate`, `benign`, `safe` = legitimate

## 🔧 Manual Column Selection

If the script can't auto-detect columns, it will ask you:

```
Available columns: ['url', 'label', 'type', 'domain']
Enter URL column name (or press Enter for 'url'): 
Enter label column name (or press Enter for 'label'):
```

## 📊 Example Usage

```bash
# Basic training
python train_kaggle.py data/kaggle_dataset.zip

# Specify custom output path
python train_kaggle.py data/kaggle_dataset.zip --output my_model.pkl
```

## ✅ After Training

The model will be saved to `phishsense/models/phishing_model.pkl` and will be automatically used by the CLI:

```bash
python phishsense_cli.py https://example.com
```

## 🎯 Improving Accuracy

If phishing URLs are showing as safe, try:

1. **Use a larger dataset** (10,000+ URLs recommended)
2. **Balance your dataset** (similar number of phishing and legitimate URLs)
3. **Retrain with better data** (remove duplicates, clean URLs)
4. **Check the model accuracy** after training (should be >85%)

## 🔍 Troubleshooting

### Issue: "No CSV files found in ZIP"
- Make sure your ZIP contains CSV files
- Check if files are in subdirectories

### Issue: "Column not found"
- The script will show available columns
- Enter the correct column name when prompted

### Issue: "No URLs loaded"
- Check if your CSV has the correct format
- Verify URL column contains valid URLs
- Check file encoding (should be UTF-8)

### Issue: Low accuracy
- Use more training data
- Ensure balanced dataset (50/50 phishing/legitimate)
- Check data quality (remove invalid URLs)

## 📈 Expected Results

After training, you should see:

```
Model Accuracy: 0.9234 (92.34%)

Classification Report:
              precision    recall  f1-score   support

 Legitimate       0.95      0.92      0.93      2000
    Phishing       0.91      0.94      0.92      2000
```

---

**Happy Training! 🚀**


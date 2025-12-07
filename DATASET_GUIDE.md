# Dataset Guide for PhishSense

## 📦 Supported Dataset Formats

PhishSense supports multiple dataset formats for training:

### 1. Plain Text Files (.txt)
- **Format**: One URL per line
- **Example**: `data/phishing_urls.txt`

```
https://suspicious-site.tk/verify
http://phishing-example.ml/login
https://fake-bank.ga/update
```

### 2. ZIP Files (.zip) ✅
- **Format**: ZIP archive containing text files
- **Supported files inside ZIP**: `.txt`, `.csv`
- **Example**: `data/phishing_urls.zip`

## 📝 Creating ZIP Datasets

### Method 1: Using Command Line

```bash
# Create a ZIP file from text files
zip data/phishing_urls.zip data/phishing_urls.txt
zip data/legitimate_urls.zip data/legitimate_urls.txt

# Or combine multiple files
zip data/phishing_urls.zip data/phishing1.txt data/phishing2.txt
```

### Method 2: Using Python

```python
import zipfile

# Create ZIP from text file
with zipfile.ZipFile('data/phishing_urls.zip', 'w') as zipf:
    zipf.write('data/phishing_urls.txt', 'phishing_urls.txt')

# Add multiple files
with zipfile.ZipFile('data/datasets.zip', 'w') as zipf:
    zipf.write('data/phishing_urls.txt', 'phishing.txt')
    zipf.write('data/legitimate_urls.txt', 'legitimate.txt')
```

## 🚀 Using ZIP Datasets

### Training with ZIP Files

```python
from phishsense.train_model import train_model

# Use ZIP files directly
train_model(
    phishing_file='data/phishing_urls.zip',
    legitimate_file='data/legitimate_urls.zip'
)
```

### Command Line

```bash
# The script automatically detects ZIP files
python -m phishsense.train_model
```

## 📊 Dataset Structure

### Recommended Structure

```
data/
├── phishing_urls.txt          # Plain text (small datasets)
├── legitimate_urls.txt        # Plain text (small datasets)
├── phishing_urls.zip          # ZIP format (large datasets)
└── legitimate_urls.zip        # ZIP format (large datasets)
```

### ZIP File Contents

Your ZIP file can contain:
- Single `.txt` file with URLs
- Multiple `.txt` files (all will be read)
- `.csv` files (first column will be read)

**Example ZIP structure:**
```
phishing_urls.zip
├── urls.txt
└── more_urls.txt
```

## 🔍 Finding Datasets

### Public Phishing URL Datasets

1. **PhishTank** (https://www.phishtank.com/)
   - Free phishing URL database
   - Requires registration for API access

2. **OpenPhish** (https://openphish.com/)
   - Community-driven phishing database
   - Free access available

3. **URLhaus** (https://urlhaus.abuse.ch/)
   - Malware URL database
   - Free API access

4. **GitHub Repositories**
   - Search for "phishing URLs dataset"
   - Many open-source collections available

### Legitimate URL Sources

- **Alexa Top Sites** (legacy)
- **Tranco List** (https://tranco-list.eu/)
- **Common Crawl** (https://commoncrawl.org/)
- **Your own curated list**

## 📥 Downloading and Preparing Datasets

### Example: Download and Prepare PhishTank Data

```python
import requests
import zipfile

# Download PhishTank data (example)
url = "https://data.phishtank.com/data/online-valid.csv"
response = requests.get(url)

# Save to file
with open('data/phishing_raw.csv', 'wb') as f:
    f.write(response.content)

# Extract URLs and create ZIP
urls = []
with open('data/phishing_raw.csv', 'r', encoding='utf-8') as f:
    for line in f:
        # Extract URL from CSV (adjust based on CSV structure)
        url = line.split(',')[1]  # Adjust index as needed
        if url.startswith('http'):
            urls.append(url.strip())

# Save to text file
with open('data/phishing_urls.txt', 'w') as f:
    f.write('\n'.join(urls))

# Create ZIP
with zipfile.ZipFile('data/phishing_urls.zip', 'w') as zipf:
    zipf.write('data/phishing_urls.txt', 'phishing_urls.txt')
```

## ✅ Dataset Quality Tips

1. **Balance**: Try to have similar numbers of phishing and legitimate URLs
2. **Diversity**: Include various types of phishing (banking, social media, etc.)
3. **Clean Data**: Remove duplicates and invalid URLs
4. **Recent Data**: Use recent URLs for better detection of current threats
5. **Validation**: Manually verify a sample to ensure quality

## 🧹 Cleaning Your Dataset

```python
import re
from urllib.parse import urlparse

def clean_urls(input_file, output_file):
    """Clean and validate URLs"""
    valid_urls = []
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            url = line.strip()
            
            # Basic validation
            if not url:
                continue
            
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Validate URL format
            try:
                parsed = urlparse(url)
                if parsed.netloc:
                    valid_urls.append(url)
            except:
                continue
    
    # Remove duplicates
    valid_urls = list(set(valid_urls))
    
    # Save
    with open(output_file, 'w') as f:
        f.write('\n'.join(valid_urls))
    
    print(f"Cleaned {len(valid_urls)} valid URLs")

# Usage
clean_urls('data/phishing_raw.txt', 'data/phishing_urls.txt')
```

## 📈 Recommended Dataset Sizes

- **Minimum**: 100 phishing + 100 legitimate URLs
- **Good**: 1,000 phishing + 1,000 legitimate URLs
- **Excellent**: 10,000+ phishing + 10,000+ legitimate URLs
- **Production**: 100,000+ URLs (use ZIP format)

## 🔒 Privacy and Security

⚠️ **Important**: 
- Only use datasets you have permission to use
- Be careful with datasets containing sensitive information
- Consider data privacy regulations (GDPR, etc.)
- Don't commit large datasets to public repositories

## 💡 Tips

1. **Start Small**: Begin with small datasets to test, then scale up
2. **Version Control**: Keep track of dataset versions
3. **Backup**: Always backup your datasets
4. **Documentation**: Document where your datasets came from
5. **Testing**: Split your data for training and testing

## 🆘 Troubleshooting

**Issue**: "Could not read from ZIP"
- **Solution**: Ensure ZIP file is not corrupted and contains text files

**Issue**: "No URLs loaded"
- **Solution**: Check file encoding (UTF-8 recommended)

**Issue**: "Memory error with large ZIP"
- **Solution**: Process in batches or use smaller chunks

---

Happy training! 🚀


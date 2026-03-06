# Phishing-off

Phishing-off is a browser extension that detects potentially malicious or phishing websites using a machine learning model trained on a large dataset of URLs.

The extension analyzes the current website URL and sends it to a local API that evaluates whether the site is safe or potentially phishing.

---

## Features

* Scan the current website directly from the browser
* Analyze suspicious links pasted from emails or messages
* Machine learning based phishing detection
* Risk score generation for websites
* Structured security report showing URL indicators
* Flask API backend for model inference
* Lightweight browser extension interface

---

## How It Works

1. The browser extension reads the current tab URL.
2. The URL is sent to a local Flask API.
3. The API extracts security-related features from the URL.
4. A trained machine learning model analyzes the features.
5. The result is returned to the extension and displayed to the user.

System architecture:

Browser Extension → Flask API → Feature Extraction → Machine Learning Model → Prediction

---

## Requirements

Install the required Python packages:

```
pip install flask pandas scikit-learn flask-cors
```

---

## Installation

### 1. Clone the repository

```
git clone https://github.com/Ayn-qt/Phishing-off.git
cd Phishing-off
```

### 2. Train the model

Run the training script to generate the trained model file.

```
python phishing_detector.py
```

This will create:

```
phishing_model.pkl
```

### 3. Start the API server

```
python api.py
```

The server will run at:

```
http://127.0.0.1:5000
```

---

## Loading the Extension

1. Open your browser.

For Brave:

```
brave://extensions
```

For Chrome:

```
chrome://extensions
```

2. Enable **Developer Mode**.
3. Click **Load Unpacked**.
4. Select the `extension` folder from this project.

The extension will now appear in your browser toolbar.

---

## Using the Extension

1. Open any website.
2. Click the extension icon.
3. Click **Check Website**.
4. The extension will display whether the website appears safe or phishing.

---

## Example Output

Safe website:

```
SAFE WEBSITE
Confidence: 95%
```

Phishing website:

```
PHISHING WEBSITE DETECTED
Confidence: 92%
```

---

## Notes

The machine learning model file and dataset are not included in the repository due to file size limitations.
Users must generate the trained model locally by running the training script.

---

## Future Improvements

* Automatic scanning when a webpage loads
* Domain reputation checks
* External threat intelligence integration
* Improved user interface
* Performance optimization

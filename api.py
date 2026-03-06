from flask import Flask, request, jsonify
import pickle
import pandas as pd
from features import extract_features
from flask_cors import CORS
from urllib.parse import urlparse
import re

app = Flask(__name__)
CORS(app)

# Load trained model
with open("phishing_model.pkl", "rb") as f:
    model, feature_names = pickle.load(f)


# ---------- SECURITY CHECKS ----------

def check_ssl(url):
    return url.startswith("https")


def check_ip(url):
    return bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url))


def check_keywords(url):
    keywords = ["login", "verify", "secure", "update", "confirm", "account", "bank"]
    return any(k in url.lower() for k in keywords)


# ---------- API ----------

@app.route("/predict", methods=["POST"])
def predict():

    data = request.get_json()
    url = data.get("url")

    # ML prediction
    features = extract_features(url)
    df = pd.DataFrame([features], columns=feature_names)

    prediction = model.predict(df)[0]
    probability = model.predict_proba(df)[0]

    # additional checks
    ssl_valid = check_ssl(url)
    ip_flag = check_ip(url)
    keyword_flag = check_keywords(url)

    # risk score calculation
    risk = 0

    if not ssl_valid:
        risk += 30

    if ip_flag:
        risk += 30

    if keyword_flag:
        risk += 20

    if prediction == 1:
        risk += 30

    risk = min(risk, 100)

    status = "PHISHING" if risk > 50 else "SAFE"

    return jsonify({
        "url": url,
        "status": status,
        "risk_score": risk,
        "details": {
            "ssl": ssl_valid,
            "ip_address": ip_flag,
            "keywords": keyword_flag
        }
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
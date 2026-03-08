#Ayaan Shaikh
#20230802420
#Mini Project: Phishing URL Detection Bot

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import re
import pickle
import numpy as np

def extract_features(url):
    try:
        return [
            len(url),
            1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url) else 0,
            sum(url.count(c) for c in ['-', '_', '?', '=', '&', '%', '@']),
            1 if url.startswith("https") else 0,
            1 if "www" in url else 0,
            1 if ".com" in url else 0,
            sum(c.isdigit() for c in url),
            url.count('.'),
            url.count('-'),
            1 if any(k in url.lower() for k in ["login", "verify", "secure", "update", "confirm", "account", "bank"]) else 0,
            1 if any(url.lower().endswith(t) for t in [".xyz", ".top", ".win", ".support", ".club", ".info"]) else 0,
            1 if any(s in url.lower() for s in ["bit.ly", "goo.gl", "tinyurl", "t.co", "ow.ly"]) else 0,
            len(set(url)) / len(url) if len(url) > 0 else 0,
            1 if '@' in url else 0,
            1 if url.count('//') > 1 else 0
        ]
    except:
        return [0] * 15

feature_names = ["length", "has_ip", "special_chars", "is_https", "has_www", "has_com",
                 "digits", "dots", "hyphens", "keyword_flag", "tld_flag", "short_flag",
                 "url_entropy", "has_at", "double_slash"]

print("Loading dataset...")
chunks = []
for chunk in pd.read_csv("phishing_site_url.csv", chunksize=50000):
    chunks.append(chunk)
df = pd.concat(chunks, ignore_index=True)
print(f"Loaded {len(df):,} URLs")


df.columns = df.columns.str.strip()
df = df[["URL", "Label"]]
df.columns = ["url", "label"]

label_map = {"good": 0, "legit": 0, "safe": 0, "benign": 0, "legitimate": 0,
             "bad": 1, "phishing": 1, "malicious": 1, "defacement": 1, "spam": 1}
df["label"] = df["label"].str.lower().str.strip().map(label_map)
df = df.dropna(subset=["label"]).astype({"label": int})

print(f"Safe: {(df['label']==0).sum():,}, Phishing: {(df['label']==1).sum():,}")


if len(df) > 150000:
    print("Sampling 150k URLs...")
    df = pd.concat([
        df[df['label']==0].sample(75000, random_state=42),
        df[df['label']==1].sample(75000, random_state=42)
    ]).sample(frac=1, random_state=42).reset_index(drop=True)


print("Extracting features...")
X = pd.DataFrame([extract_features(url) for url in df["url"]], columns=feature_names)
y = df["label"].values


print("Training model...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

model = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)


preds = model.predict(X_test)
accuracy = accuracy_score(y_test, preds)

print(f"\n{'='*50}")
print(f"Accuracy: {accuracy*100:.2f}%\n")
print(classification_report(y_test, preds, target_names=["Safe", "Phishing"]))

cm = confusion_matrix(y_test, preds)
print(f"\nConfusion Matrix:")
print(f"True Negatives: {cm[0][0]:,} | False Positives: {cm[0][1]:,}")
print(f"False Negatives: {cm[1][0]:,} | True Positives: {cm[1][1]:,}")


with open("phishing_model.pkl", "wb") as f:
    pickle.dump((model, feature_names), f)
print("\n✓ Model saved as 'phishing_model.pkl'")


print(f"\n{'='*50}")
print("PHISHING URL CHECKER")
print(f"{'='*50}\n")

while True:
    url = input("Enter URL (or 'exit'): ").strip()
    
    if url.lower() == "exit":
        print("\n Goodbye!")
        break
    
    if not url:
        continue
    
    url_df = pd.DataFrame([extract_features(url)], columns=feature_names)
    pred = model.predict(url_df)[0]
    prob = model.predict_proba(url_df)[0]
    
    print(f"\n{'─'*50}")
    if pred == 1:
        print(f"  WARNING: PHISHING ({prob[1]*100:.1f}% confidence)")
    else:
        print(f" SAFE ({prob[0]*100:.1f}% confidence)")
    print(f"{'─'*50}\n")

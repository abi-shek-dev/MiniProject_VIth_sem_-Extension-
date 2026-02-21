from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import re
from classifier import URLFeatureExtractor  # Ensure this file is in your folder

app = Flask(__name__)
CORS(app)

# ==========================================
# 1. LOAD MODELS & CONFIGURATION
# ==========================================
try:
    model = joblib.load('models/model.pkl')
    feature_cols = joblib.load('models/features.pkl')
    extractor = URLFeatureExtractor()
    print("✅ Model and Feature Extractor initialized.")
except Exception as e:
    print(f"❌ Initialization Error: {e}")

CLASS_MAP = {0: "Safe", 1: "Defacement", 2: "Phishing", 3: "Malicious"}

# Major sites that never need an AI check
WHITELIST = [
    "google.com", "google.co.in", "youtube.com", "facebook.com", 
    "linkedin.com", "github.com", "microsoft.com", "apple.com"
]

# Trusted dev platforms (Prevents flagging portfolios)
INFRA_PROVIDERS = ["web.app", "vercel.app", "github.io", "netlify.app", "pages.dev"]

# ==========================================
# 2. CONTENT SCANNER (The Scraper)
# ==========================================
def scan_page_content(url):
    """Visits the site and checks the actual HTML for phishing signals."""
    try:
        # We use a short timeout to keep the extension fast
        response = requests.get(url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for password inputs (High risk on unknown domains)
        has_password = 1 if soup.find('input', {'type': 'password'}) else 0
        
        # Check for external forms (Data sent to a different domain)
        forms = soup.find_all('form')
        ext_form = 0
        domain = urlparse(url).netloc
        for f in forms:
            action = f.get('action', '')
            if action.startswith('http') and domain not in action:
                ext_form = 1
        
        # Check for brand mentions in text
        text = soup.get_text().lower()
        brands = ['login', 'verify', 'account', 'bank', 'secure']
        brand_score = sum(1 for b in brands if b in text)
        
        return {"has_password": has_password, "ext_form": ext_form, "brand_score": brand_score}
    except:
        return {"has_password": 0, "ext_form": 0, "brand_score": 0}

# ==========================================
# 3. THE PREDICTION ROUTE
# ==========================================
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    domain = urlparse(url).netloc.lower().replace('www.', '')

    # --- LAYER 1: WHITELIST ---
    if any(white_domain in domain for white_domain in WHITELIST):
        return jsonify({"url": url, "status": "Safe", "confidence": 1.0, "method": "Whitelist"})

    # --- LAYER 2: HTML SCRAPING ---
    content = scan_page_content(url)

    # --- LAYER 3: MACHINE LEARNING (URL Analysis) ---
    features_list = extractor.extract_all(url)
    features_df = pd.DataFrame([features_list], columns=feature_cols)
    
    probs = model.predict_proba(features_df)[0]
    ai_idx = np.argmax(probs)
    ai_confidence = float(probs[ai_idx])
    ai_status = CLASS_MAP.get(ai_idx, "Safe")

    # --- LAYER 4: HYBRID LOGIC (The "Decision Maker") ---
    final_status = ai_status

    # 1. If it's a portfolio on web.app/vercel, be more lenient
    if any(provider in domain for provider in INFRA_PROVIDERS):
        # Only flag it if the HTML actually looks like a phishing trap
        if ai_status == "Phishing" and content['has_password'] == 0:
            final_status = "Safe"
    
    # 2. If the HTML has a password field + external form, it's 100% Phishing
    if content['has_password'] and content['ext_form']:
        final_status = "Phishing"
        ai_confidence = 1.0

    print(f"🔍 Checked: {url} | AI: {ai_status} | Final: {final_status}")

    return jsonify({
        "url": url,
        "status": final_status,
        "confidence": ai_confidence,
        "html_flags": content
    })

if __name__ == '__main__':
    app.run(port=5000, debug=True)
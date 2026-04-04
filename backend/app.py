import os
import requests
import urllib.parse
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────
# 1. STATE LOADING
# ─────────────────────────────────────────────────────────
WHITELIST = [
    "google.com", "whatsapp.com", "snapchat.com", "facebook.com", 
    "youtube.com", "linkedin.com", "bing.com", "yahoo.com",
    "amazon.com", "microsoft.com", "apple.com", "instagram.com",
    "twitter.com", "x.com", "github.com", "netflix.com",
    "reddit.com", "wikipedia.org", "chatgpt.com", "openai.com"
]

print("✅ SiteShield API & Hunter Engine Online (No ML)")

# ─────────────────────────────────────────────────────────
# 2. API SERVICE LAYERS
# ─────────────────────────────────────────────────────────
def check_google_safe_browsing(url):
    key = os.getenv('GOOGLE_SAFE_BROWSING_API')
    if not key or "paste" in key.lower():
        return None
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
    payload = {
        "client": {"clientId": "SiteShield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(endpoint, json=payload, timeout=2)
        if r.status_code == 200 and r.json().get('matches'):
            return "Malicious"
    except: pass
    return None

def check_virustotal(domain):
    key = os.getenv('VIRUSTOTAL_API_KEY')
    if not key or "paste" in key.lower():
        return None
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": key}
        r = requests.get(url, headers=headers, timeout=2)
        if r.status_code == 200:
            stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            phishing = stats.get('phishing', 0)
            if malicious > 0 or phishing > 0:
                return "Malicious"
    except: pass
    return None

# ─────────────────────────────────────────────────────────
# 3. MASTER ENDPOINT
# ─────────────────────────────────────────────────────────
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data:
        return jsonify({"status": "Error", "message": "No data received"}), 400

    dna = data.get('dna', {})
    url = dna.get('url') or data.get('url')
    
    if not url:
        return jsonify({"status": "Error", "message": "No URL provided"}), 400

    domain = urllib.parse.urlparse(url).netloc.lower().replace('www.', '')

    # == LAYER 1: WHITELIST ==
    if any(white in domain for white in WHITELIST):
        return jsonify({"url": url, "status": "Safe", "ai_score": "100%", "hunter_risk": 0, "method": "Whitelist"})

    # == LAYER 2: API CHECKS ==
    gsb = check_google_safe_browsing(url)
    if gsb:
        return jsonify({"url": url, "status": "Phishing", "ai_score": "100%", "hunter_risk": 100, "method": "Google Safe Browsing"})
        
    vt = check_virustotal(domain)
    if vt:
        return jsonify({"url": url, "status": "Malicious", "ai_score": "100%", "hunter_risk": 100, "method": "VirusTotal"})
    
    # == LAYER 3: HUNTER (BEHAVIORAL RISK) ==
    risk_score = 0
    if dna.get('shadow_forms', 0) > 0: risk_score += 60 
    if dna.get('has_password'): risk_score += 30
    if dna.get('hidden_iframes', 0) > 0: risk_score += 20
    if dna.get('is_obfuscated'): risk_score += 15

    final_status = "Safe"
    if risk_score >= 70:
        final_status = "Malicious"
    elif risk_score >= 30:
        final_status = "Suspicious"

    return jsonify({
        "url": url,
        "status": final_status,
        "ai_score": "API Only",
        "hunter_risk": risk_score,
        "method": "API + Hunter Scan"
    })

if __name__ == '__main__':
    app.run(port=5000, debug=False)
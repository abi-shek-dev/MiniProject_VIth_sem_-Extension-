import os
import requests
import urllib.parse
from datetime import datetime
from difflib import SequenceMatcher
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

print("✅ SiteShield Ultimate Engine Online (APIs + Age + Typosquatting)")

# ─────────────────────────────────────────────────────────
# 2. LOCAL CYBERSECURITY ENGINES
# ─────────────────────────────────────────────────────────

def check_domain_age(domain):
    """Hits public RDAP registry to find domain creation date."""
    try:
        r = requests.get(f'https://rdap.org/domain/{domain}', timeout=3)
        if r.status_code == 200:
            events = r.json().get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    creation_date_str = event.get('eventDate')
                    if creation_date_str:
                        date_obj = datetime.strptime(creation_date_str.split('T')[0], '%Y-%m-%d')
                        age_days = (datetime.now() - date_obj).days
                        
                        # Added Print Logic for User Terminal
                        print(f"🌍 WHOIS Scan | Domain: {domain} | Created: {date_obj.date()} | Age: {age_days} days")
                        
                        return age_days
    except Exception as e: 
        print(f"⚠️ WHOIS Error for {domain}: {e}")
    return None

def check_typosquatting(domain, whitelist):
    """Mathematical string comparison against major brands."""
    parts = domain.split('.')
    if len(parts) < 2: return False, None
    base_domain = parts[-2]
    
    for white in whitelist:
        white_base = white.split('.')[-2]
        if base_domain == white_base: continue
        
        # Levenshtein simulation via SequenceMatcher
        ratio = SequenceMatcher(None, base_domain, white_base).ratio()
        
        # If it's over 80% similar to a major brand (e.g., amaz0n.com -> amazon.com)
        if ratio >= 0.8:
            return True, white
            
    return False, None

# ─────────────────────────────────────────────────────────
# 3. EXTERNAL API SERVICE LAYERS
# ─────────────────────────────────────────────────────────
def check_google_safe_browsing(url):
    key = os.getenv('GOOGLE_SAFE_BROWSING_API')
    if not key or "paste" in key.lower(): return None
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
        if r.status_code == 200 and r.json().get('matches'): return "Malicious"
    except: pass
    return None

def check_virustotal(domain):
    key = os.getenv('VIRUSTOTAL_API_KEY')
    if not key or "paste" in key.lower(): return None
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": key}
        r = requests.get(url, headers=headers, timeout=2)
        if r.status_code == 200:
            stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            phishing = stats.get('phishing', 0)
            if malicious > 0 or phishing > 0: return "Malicious"
    except: pass
    return None

# ─────────────────────────────────────────────────────────
# 4. MASTER ENDPOINT
# ─────────────────────────────────────────────────────────
@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if not data: return jsonify({"status": "Error", "message": "No data received"}), 400

    dna = data.get('dna', {})
    url = dna.get('url') or data.get('url')
    if not url: return jsonify({"status": "Error", "message": "No URL provided"}), 400

    domain = urllib.parse.urlparse(url).netloc.lower().replace('www.', '')

    # == LAYER 0: FORCE PRINT DOMAIN AGE FOR PRESENTATION ==
    domain_age = check_domain_age(domain)
    age_risk = 0
    age_method_tag = ""
    if domain_age is not None:
        if domain_age < 30:
            age_risk += 50
            age_method_tag = " (Brand New Domain!)"
        elif domain_age < 180:
            age_risk += 20

    # == LAYER 1: WHITELIST Bouncer ==
    if any(white == domain for white in WHITELIST):
        return jsonify({"url": url, "status": "Safe", "ai_score": "100%", "hunter_risk": 0, "method": "Whitelist"})

    # == LAYER 2: TYPOSQUATTING (Lookalike) Check ==
    is_spoof, real_brand = check_typosquatting(domain, WHITELIST)
    if is_spoof:
        return jsonify({"url": url, "status": "Phishing", "ai_score": "100%", "hunter_risk": 95, "method": f"Typosquatting (Spoofing {real_brand})"})

    # == LAYER 4: DNS / API CHECKS ==
    gsb = check_google_safe_browsing(url)
    if gsb:
        return jsonify({"url": url, "status": "Phishing", "ai_score": "100%", "hunter_risk": 100, "method": "Google Safe Browsing"})
        
    vt = check_virustotal(domain)
    if vt:
        return jsonify({"url": url, "status": "Malicious", "ai_score": "100%", "hunter_risk": 100, "method": "VirusTotal"})
    
    # == LAYER 5: DOM HUNTER (Behavioral Risk) ==
    risk_score = age_risk
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
        "ai_score": "API + WHOIS",
        "hunter_risk": min(risk_score, 100), # Cap at 100
        "method": f"Hunter + Age Scan{age_method_tag}"
    })

if __name__ == '__main__':
    app.run(port=5000, debug=False)
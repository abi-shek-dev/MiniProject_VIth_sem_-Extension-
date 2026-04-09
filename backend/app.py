import os
import requests
import urllib.parse
from datetime import datetime
from difflib import SequenceMatcher
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from classifier import ContentScanner

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

# Load local blacklist
BLACKLIST = []
BLACKLIST_PATH = os.path.join('data', 'blacklist.txt')
if os.path.exists(BLACKLIST_PATH):
    with open(BLACKLIST_PATH, 'r') as f:
        BLACKLIST = [line.strip().lower() for line in f if line.strip()]

print(f"✅ SiteShield Ultimate Engine Online (Whitelist: {len(WHITELIST)}, Blacklist: {len(BLACKLIST)})")

# ─────────────────────────────────────────────────────────
# 2. LOCAL CYBERSECURITY ENGINES
# ─────────────────────────────────────────────────────────

def check_domain_age(domain):
    """Hits public RDAP registry to find domain creation date. Returns (age_days, created_date_str) tuple."""
    try:
        # Increased timeout to 7 seconds. Free public RDAP gets slow sometimes!
        r = requests.get(f'https://rdap.org/domain/{domain}', timeout=7)
        if r.status_code == 200:
            events = r.json().get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    creation_date_str = event.get('eventDate')
                    if creation_date_str:
                        date_obj = datetime.strptime(creation_date_str.split('T')[0], '%Y-%m-%d')
                        age_days = (datetime.now() - date_obj).days
                        created_str = date_obj.strftime('%d %b %Y')  # e.g. "15 Sep 1997"
                        
                        # Terminal print for presentation
                        print(f"🌍 WHOIS Scan | Domain: {domain} | Created: {created_str} | Age: {age_days} days")
                        
                        return age_days, created_str
    except Exception as e: 
        print(f"⚠️ WHOIS Error for {domain}: {e}")
    return None, None

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

def check_url_heuristics(domain, url):
    """Analyzes the URL itself for scam patterns — no API needed."""
    import re
    risk = 0
    reasons = []
    
    parts = domain.split('.')
    base = parts[-2] if len(parts) >= 2 else domain
    tld = parts[-1] if len(parts) >= 2 else ''
    full_domain = domain.lower()
    
    # 1. Suspicious TLDs commonly abused by scammers
    high_risk_tlds = ['cc', 'xyz', 'top', 'vip', 'cfd', 'icu', 'buzz', 'sbs', 'rest', 'surf']
    medium_risk_tlds = ['shop', 'club', 'online', 'site', 'ltd', 'pro', 'plus']
    if tld in high_risk_tlds:
        risk += 35
        reasons.append(f'High-risk TLD (.{tld})')
    elif tld in medium_risk_tlds:
        risk += 20
        reasons.append(f'Suspicious TLD (.{tld})')
    
    # 2. Gibberish domain name detection (low vowel ratio = random chars)
    vowels = sum(1 for c in base if c in 'aeiou')
    consonants = sum(1 for c in base if c.isalpha() and c not in 'aeiou')
    
    if len(base) > 3:
        vowel_ratio = vowels / len(base)
        if vowel_ratio <= 0.2:  # Fixed: was < 0.2, now catches hdajx (ratio 0.2)
            risk += 35
            reasons.append('Gibberish domain name')
        elif vowel_ratio <= 0.25:
            risk += 20
            reasons.append('Low readability domain')
    
    # 3. Consonant clusters (3+ consonants in a row = not a real word)
    if re.search(r'[bcdfghjklmnpqrstvwxyz]{4,}', base):
        risk += 25
        reasons.append('Unpronounceable domain')
    
    # 4. Short meaningless domains (hdajx, fgnbg, xskym)
    if len(base) <= 5 and vowels <= 1:
        risk += 25
        reasons.append('Very short random domain')
    
    # 5. Domain has numbers mixed with letters (coin6s, coin8v, my6us)
    if re.search(r'[a-z]\d|\d[a-z]', base):
        risk += 20
        reasons.append('Mixed letters+numbers')
    
    # 6. Subdomain depth (hk0017.jinanly.top = deep subdomain)
    if len(parts) > 3:
        risk += 20
        reasons.append('Deep subdomain chain')
    
    # 7. Scam keywords in the domain itself
    scam_words = [
        'pay', 'coin', 'trade', 'fx', 'mall', 'shop', 'reward', 'invest',
        'crypto', 'earn', 'profit', 'deal', 'hub', 'task', 'review',
        'finance', 'capital', 'asset', 'trust', 'secure', 'fast',
        'lucky', 'order', 'gift', 'prize', 'win', 'bonus'
    ]
    matches = [w for w in scam_words if w in full_domain]
    if len(matches) >= 2:
        risk += 35
        reasons.append(f'Multiple scam keywords: {", ".join(matches)}')
    elif len(matches) == 1:
        risk += 20
        reasons.append(f'Scam keyword: {matches[0]}')
    
    # 8. Extremely long domain names (often auto-generated scam domains)
    if len(base) > 20:
        risk += 20
        reasons.append('Unusually long domain name')
    
    # 9. No HTTPS
    if not url.startswith('https'):
        risk += 10
        reasons.append('No HTTPS')
    
    # 10. Domain looks like it's impersonating a brand with extra words
    brand_fragments = ['amazon', 'google', 'apple', 'paypal', 'netflix', 'microsoft', 'facebook', 'instagram']
    for brand in brand_fragments:
        if brand in base and base != brand:
            risk += 30
            reasons.append(f'Contains brand name: {brand}')
            break
    
    if reasons:
        print(f"🧬 URL Heuristics | {domain} | Risk: {risk} | Flags: {', '.join(reasons)}")
    
    return risk

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
        r = requests.get(url, headers=headers, timeout=3)
        if r.status_code == 200:
            stats = r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            phishing = stats.get('phishing', 0)
            suspicious = stats.get('suspicious', 0)
            # Need 2+ engines to flag
            if malicious >= 2 or phishing >= 2 or suspicious >= 3: return "Malicious"
    except: pass
    return None

def check_urlscan(domain):
    """Uses URLScan.io to check domain reputation."""
    key = os.getenv('URLSCAN_API_KEY')
    if not key or "paste" in key.lower(): return None
    try:
        headers = {"API-Key": key}
        r = requests.get(f'https://urlscan.io/api/v1/search/?q=domain:{domain}', headers=headers, timeout=3)
        if r.status_code == 200:
            results = r.json().get('results', [])
            for result in results[:3]:  # Check latest 3 scans
                verdicts = result.get('verdicts', {}).get('overall', {})
                if verdicts.get('malicious'):
                    print(f"🛡️ URLScan.io flagged {domain} as malicious!")
                    return "Malicious"
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
    domain_age, domain_created = check_domain_age(domain)
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
        return jsonify({"url": url, "status": "Safe", "ai_score": "100%", "hunter_risk": 0, "method": "Whitelist", "domain_created": domain_created or "N/A", "domain_age_days": domain_age})

    # == LAYER 1.5: BLACKLIST Check ==
    if any(black in domain for black in BLACKLIST):
        return jsonify({"url": url, "status": "Scam", "ai_score": "100%", "hunter_risk": 100, "method": "Local Blacklist", "domain_created": domain_created or "N/A", "domain_age_days": domain_age})

    # == LAYER 2: TYPOSQUATTING (Lookalike) Check ==
    is_spoof, real_brand = check_typosquatting(domain, WHITELIST)
    if is_spoof:
        return jsonify({"url": url, "status": "Phishing", "ai_score": "100%", "hunter_risk": 95, "method": f"Typosquatting (Spoofing {real_brand})", "domain_created": domain_created or "N/A", "domain_age_days": domain_age})

    # == LAYER 4: DNS / API CHECKS ==
    gsb = check_google_safe_browsing(url)
    if gsb:
        return jsonify({"url": url, "status": "Phishing", "ai_score": "100%", "hunter_risk": 100, "method": "Google Safe Browsing", "domain_created": domain_created or "N/A", "domain_age_days": domain_age})
        
    vt = check_virustotal(domain)
    if vt:
        return jsonify({"url": url, "status": "Malicious", "ai_score": "100%", "hunter_risk": 100, "method": "VirusTotal", "domain_created": domain_created or "N/A", "domain_age_days": domain_age})

    # == LAYER 4.5: URLScan.io ==
    us = check_urlscan(domain)
    if us:
        return jsonify({"url": url, "status": "Malicious", "ai_score": "100%", "hunter_risk": 100, "method": "URLScan.io", "domain_created": domain_created or "N/A", "domain_age_days": domain_age})

    # == LAYER 5: URL HEURISTICS (Scam Pattern Analysis) ==
    url_risk = check_url_heuristics(domain, url)

    # == LAYER 6: WEB SCRAPING (Deep Page Analysis) ==
    scrape = ContentScanner.scan_page(url)
    scrape_risk = scrape.get('scrape_risk_score', 0)

    # == LAYER 7: DOM HUNTER (Behavioral Risk from Extension) ==
    risk_score = age_risk + url_risk + scrape_risk
    if dna.get('shadow_forms', 0) > 0: risk_score += 60 
    if dna.get('hidden_iframes', 0) > 0: risk_score += 20
    if dna.get('is_obfuscated'): risk_score += 10
    if dna.get('has_password') and risk_score > 0: risk_score += 20

    final_status = "Safe"
    if risk_score >= 55:
        final_status = "Scam"
    elif risk_score >= 35:
        final_status = "Suspicious"

    print(f"⚖️ VERDICT | {domain} | Age Risk: {age_risk} | URL Risk: {url_risk} | Scrape Risk: {scrape_risk} | Total: {risk_score} → {final_status}")

    return jsonify({
        "url": url,
        "status": final_status,
        "ai_score": "Heuristic + Scrape",
        "hunter_risk": min(risk_score, 100),
        "method": f"URL Analysis + Scrape{age_method_tag}",
        "domain_created": domain_created or "N/A",
        "domain_age_days": domain_age,
        "scrape": {
            "page_title": scrape.get('page_title', ''),
            "keywords_found": scrape.get('keyword_score', 0),
            "external_forms": scrape.get('external_forms', 0),
            "suspicious_scripts": scrape.get('suspicious_scripts', 0),
            "brand_spoof": scrape.get('brand_found')
        }
    })

if __name__ == '__main__':
    app.run(port=5000, debug=False)
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class ContentScanner:
    """Scrapes a live webpage and extracts security-relevant signals from its HTML."""

    PHISH_KEYWORDS = [
        'login', 'signin', 'sign-in', 'bank', 'secure', 'verify', 
        'credential', 'update your', 'confirm your', 'suspended',
        'unusual activity', 'unauthorized', 'expire', 'ssn',
        'social security', 'credit card', 'debit card', 'paypal',
        'bitcoin', 'wallet', 'prize', 'winner', 'congratulations',
        'lottery', 'free gift', 'act now', 'limited time',
        'click here immediately', 'your account'
    ]

    BRAND_NAMES = [
        'google', 'facebook', 'apple', 'microsoft', 'amazon',
        'netflix', 'paypal', 'instagram', 'whatsapp', 'linkedin',
        'twitter', 'chase', 'wellsfargo', 'bankofamerica', 'citibank'
    ]

    @staticmethod
    def scan_page(url):
        """Full page scrape and analysis. Returns a risk dictionary."""
        result = {
            "scraped": False,
            "has_password": 0,
            "keyword_score": 0,
            "external_forms": 0,
            "hidden_inputs": 0,
            "suspicious_scripts": 0,
            "brand_impersonation": False,
            "brand_found": None,
            "has_https": url.startswith('https'),
            "fake_url_bar": False,
            "too_many_redirects": False,
            "page_title": "",
            "scrape_risk_score": 0
        }

        try:
            response = requests.get(
                url, timeout=5,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                allow_redirects=True
            )

            # Check for too many redirects (common phishing tactic)
            if len(response.history) >= 3:
                result["too_many_redirects"] = True

            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text().lower()
            html_raw = response.text.lower()
            original_domain = urlparse(url).netloc.lower()

            result["scraped"] = True

            # --- 1. Page Title ---
            title_tag = soup.find('title')
            result["page_title"] = title_tag.get_text().strip()[:80] if title_tag else "No Title"

            # --- 2. Password Fields ---
            password_fields = soup.find_all('input', {'type': 'password'})
            result["has_password"] = len(password_fields)

            # --- 3. Phishing Keywords in Page Text ---
            keyword_hits = 0
            for kw in ContentScanner.PHISH_KEYWORDS:
                if kw in text:
                    keyword_hits += 1
            result["keyword_score"] = keyword_hits

            # --- 4. External Form Actions (Data Exfiltration) ---
            forms = soup.find_all('form')
            external_count = 0
            for form in forms:
                action = form.get('action', '')
                if action.startswith('http') and original_domain not in action:
                    external_count += 1
            result["external_forms"] = external_count

            # --- 5. Hidden Input Fields (credential harvesting) ---
            hidden_inputs = soup.find_all('input', {'type': 'hidden'})
            result["hidden_inputs"] = len(hidden_inputs)

            # --- 6. Suspicious Scripts (obfuscated JS, eval, document.cookie) ---
            scripts = soup.find_all('script')
            sus_script_count = 0
            for script in scripts:
                code = script.get_text().lower()
                if any(x in code for x in ['eval(', 'document.cookie', 'atob(', 'fromcharcode', 'unescape(']):
                    sus_script_count += 1
            result["suspicious_scripts"] = sus_script_count

            # --- 7. Brand Impersonation ---
            for brand in ContentScanner.BRAND_NAMES:
                if brand in text and brand not in original_domain:
                    result["brand_impersonation"] = True
                    result["brand_found"] = brand
                    break

            # --- 8. Fake URL Bar Detection (common phishing trick) ---
            if 'address bar' in html_raw or 'url bar' in html_raw:
                result["fake_url_bar"] = True

            # --- CALCULATE COMPOSITE SCRAPE RISK SCORE ---
            risk = 0
            if result["external_forms"] > 0:         risk += 40
            if result["keyword_score"] >= 4:          risk += 25
            elif result["keyword_score"] >= 2:        risk += 10
            if result["suspicious_scripts"] > 0:      risk += 30
            if result["brand_impersonation"]:          risk += 25
            if result["hidden_inputs"] > 5:            risk += 15
            if result["too_many_redirects"]:           risk += 15
            if result["fake_url_bar"]:                 risk += 30
            if not result["has_https"]:                risk += 10
            # Password + brand impersonation = very suspicious combo
            if result["has_password"] > 0 and result["brand_impersonation"]:
                risk += 20

            result["scrape_risk_score"] = min(risk, 100)

            # Terminal print for presentation
            print(f"🔍 Scrape Scan | {url[:50]}... | Keywords: {keyword_hits} | ExtForms: {external_count} | SusScripts: {sus_script_count} | Brand: {result['brand_found'] or 'None'} | Risk: {risk}")

        except Exception as e:
            print(f"⚠️ Scrape Error for {url[:40]}: {e}")

        return result
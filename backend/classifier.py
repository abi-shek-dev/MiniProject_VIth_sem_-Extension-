import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

class URLFeatureExtractor:
    def extract_all(self, url):
        hostname = urlparse(url).netloc
        # Ensure the order matches exactly what we trained in test.py
        features = [
            len(url),                                     # 0: url_len
            url.count('@'),                               # 1: @
            url.count('?'),                               # 2: ?
            url.count('-'),                               # 3: -
            url.count('='),                               # 4: =
            url.count('.'),                               # 5: .
            url.count('#'),                               # 6: #
            url.count('%'),                               # 7: %
            url.count('+'),                               # 8: +
            url.count('$'),                               # 9: $
            url.count('!'),                               # 10: !
            url.count('*'),                               # 11: *
            sum(c.isdigit() for c in url),                # 12: digits
            sum(c.isalpha() for c in url),                # 13: letters
            1 if hostname == "" else 0,                   # 14: abnormal_url
            1 if url.startswith('https') else 0,          # 15: https
            1 if any(x in url for x in ['bit.ly', 't.co', 'goo.gl']) else 0, # 16: Shortining_Service
            1 if re.match(r"^\d+\.\d+\.\d+\.\d+", hostname) else 0,          # 17: having_ip_address
            1,                                            # 18: web_is_live
            0,                                            # 19: web_security_score
            1 if 'login' in url.lower() else 0,           # 20: web_has_login
            1 if any(x in url.lower() for x in ['urgent', 'verify', 'account']) else 0, # 21: phish_urgency_words
            1 if any(x in url.lower() for x in ['security', 'alert', 'warn']) else 0,   # 22: phish_security_words
            0                                             # 23: phish_brand_mentions
        ]
        return features

class ContentScanner:
    @staticmethod
    def scan_page(url):
        """Scrapes the website to find phishing triggers in the HTML."""
        try:
            # We use a 3-second timeout so the browser doesn't wait forever
            response = requests.get(url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Check for Password fields (Suspicious if the URL isn't a known brand)
            has_password = 1 if soup.find('input', {'type': 'password'}) else 0
            
            # 2. Check for hidden forms or suspicious keywords in text
            phish_keywords = ['login', 'bank', 'secure', 'verify', 'credential', 'update']
            text = soup.get_text().lower()
            keyword_score = sum(1 for word in phish_keywords if word in text)
            
            # 3. Check for external form actions (Sends data to another domain)
            forms = soup.find_all('form')
            external_action = 0
            original_domain = urlparse(url).netloc
            for form in forms:
                action = form.get('action', '')
                if action.startswith('http') and original_domain not in action:
                    external_action = 1
            
            return {
                "has_password": has_password,
                "keyword_score": keyword_score,
                "external_form": external_action,
                "is_active": True
            }
        except Exception as e:
            # If the site blocks scraping or is down
            return {"has_password": 0, "keyword_score": 0, "external_form": 0, "is_active": False}
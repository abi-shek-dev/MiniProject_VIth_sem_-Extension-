import re
from urllib.parse import urlparse

class URLFeatureExtractor:
    @staticmethod
    def extract_all(url):
        # We must return the features in the EXACT SAME ORDER as feature_cols
        hostname = urlparse(url).netloc
        path = urlparse(url).path
        
        features = {
            'url_len': len(url),
            '@': url.count('@'),
            '?': url.count('?'),
            '-': url.count('-'),
            '=': url.count('='),
            '.': url.count('.'),
            '#': url.count('#'),
            '%': url.count('%'),
            '+': url.count('+'),
            '$': url.count('$'),
            '!': url.count('!'),
            '*': url.count('*'),
            'digits': sum(c.isdigit() for c in url),
            'letters': sum(c.isalpha() for c in url),
            'abnormal_url': 1 if hostname == "" else 0,
            'https': 1 if url.startswith('https') else 0,
            'Shortining_Service': 1 if any(x in url for x in ['bit.ly', 'goo.gl', 't.co']),
            'having_ip_address': 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname) else 0,
            'web_is_live': 1, # Default for real-time check
            'web_security_score': 0, # Placeholder for now
            'web_has_login': 1 if 'login' in url.lower() else 0,
            'phish_urgency_words': 1 if any(x in url.lower() for x in ['urgent', 'verify', 'account']),
            'phish_security_words': 1 if any(x in url.lower() for x in ['security', 'alert', 'warn']),
            'phish_brand_mentions': 0 # Could be expanded with a brand list
        }
        return list(features.values())
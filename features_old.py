from urllib.parse import urlparse

suspicious_keywords = ["login", "secure", "account", "update", "bank", "paypal", "verify", "confirm", "signin", "password"]

def extract_features(url):
    """Extract features from URL for phishing detection"""
    parsed = urlparse(url)
    
    return {
        "URL_Length": len(url),
        "Special_Chars": sum(url.count(c) for c in "@/?=_-"),
        "Num_Subdomains": parsed.netloc.count('.') - 1 if parsed.netloc.count('.') > 0 else 0,
        "Suspicious_Keywords": sum(k in url.lower() for k in suspicious_keywords),
        "Has_HTTPS": 1 if parsed.scheme == "https" else 0
    }
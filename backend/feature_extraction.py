import re
from urllib.parse import urlparse
import pandas as pd


SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "link", "gq", "cf", "tk", "ml"
}

URL_SHORTENERS = {
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly",
    "is.gd", "buff.ly", "adf.ly"
}


def has_ip_address(netloc: str) -> int:
    # Simple IPv4 pattern
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return int(bool(re.match(ip_pattern, netloc)))


def count_substrings(s: str, chars: str) -> int:
    return sum(s.count(c) for c in chars)


def is_url_shortener(netloc: str) -> int:
    netloc = netloc.lower()
    return int(any(short in netloc for short in URL_SHORTENERS))


def get_tld(netloc: str) -> str:
    parts = netloc.split(".")
    if len(parts) < 2:
        return ""
    return parts[-1].lower()


def extract_url_features(url: str) -> dict:
    """
    Extracts numeric + boolean features from a URL.
    """
    url = url.strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    netloc = parsed.netloc
    path = parsed.path
    query = parsed.query

    # Basic properties
    url_length = len(url)
    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_at = url.count("@")
    num_question = url.count("?")
    num_percent = url.count("%")
    num_equal = url.count("=")
    num_slash = url.count("/")
    num_digits = sum(ch.isdigit() for ch in url)

    # Flags
    has_https = int(parsed.scheme.lower() == "https")
    has_ip = has_ip_address(netloc)
    uses_shortener = is_url_shortener(netloc)
    tld = get_tld(netloc)
    suspicious_tld = int(tld in SUSPICIOUS_TLDS)

    # Path/query length
    path_length = len(path)
    query_length = len(query)

    # Count special characters
    special_chars = count_substrings(url, "~!#*;,$")
    
    return {
        "url": url,
        "url_length": url_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "num_question": num_question,
        "num_percent": num_percent,
        "num_equal": num_equal,
        "num_slash": num_slash,
        "num_digits": num_digits,
        "has_https": has_https,
        "has_ip": has_ip,
        "uses_shortener": uses_shortener,
        "suspicious_tld": suspicious_tld,
        "path_length": path_length,
        "query_length": query_length,
        "special_chars": special_chars,
    }


def extract_features_from_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Takes a DataFrame with a 'url' column and returns numerical features
    + original label (if present).
    """
    features = []
    for _, row in df.iterrows():
        f = extract_url_features(row["url"])
        if "label" in df.columns:
            f["label"] = row["label"]
        features.append(f)

    return pd.DataFrame(features)

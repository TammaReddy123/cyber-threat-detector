import os
import requests
import tldextract
import socket


# -------------------- GEO LOOKUP (ip-api.com) --------------------
def ip_to_country(ip):
    if not ip:
        return {"country": None, "latitude": None, "longitude": None}

    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,lat,lon").json()

        if res.get("status") != "success":
            return {"country": None, "latitude": None, "longitude": None}

        return {
            "country": res.get("country"),
            "latitude": res.get("lat"),
            "longitude": res.get("lon"),
        }

    except:
        return {"country": None, "latitude": None, "longitude": None}


# -------------------- DOMAIN INFO --------------------
def get_domain_info(url):
    try:
        ext = tldextract.extract(url)
        domain = ext.registered_domain or ext.domain

        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = None

        return {
            "domain": domain,
            "ip": ip,
        }
    except:
        return {"domain": None, "ip": None}


# -------------------- VIRUSTOTAL --------------------
VT_API_KEY = os.getenv("VT_API_KEY")

def scan_with_virustotal(url):
    if not VT_API_KEY:
        return {"malicious": 0, "suspicious": 0}

    try:
        upload = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers={"x-apikey": VT_API_KEY}
        ).json()

        analysis_id = upload["data"]["id"]

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers={"x-apikey": VT_API_KEY}
        ).json()

        stats = result["data"]["attributes"]["stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
        }

    except:
        return {"malicious": 0, "suspicious": 0}
    
def get_ip_geolocation(ip):
    """
    Uses VirusTotal IP API to get country + lat/lon.
    Returns dict or None.
    """
    if not VT_API_KEY or not ip:
        return None

    try:
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=10
        ).json()

        attrs = resp["data"]["attributes"]

        return {
            "country": attrs.get("country"),
            "latitude": attrs.get("latitude"),
            "longitude": attrs.get("longitude"),
        }

    except Exception:
        return None


# -------------------- BLACKLIST CHECK --------------------
def check_blacklist(url):
    """
    Check if URL contains known malicious patterns
    """
    blacklist_patterns = [
        "testsafebrowsing.appspot.com",  # Known malware test URL
        "malware",  # Generic malware indicator
        "exploit",  # Exploit indicators
        "phishing",
        "scam",
        "virus",
        "trojan"
    ]

    url_lower = url.lower()
    for pattern in blacklist_patterns:
        if pattern in url_lower:
            return True
    return False

# -------------------- RISK ENGINE --------------------
def compute_risk_score(url, predicted_label, label_probs):

    # Check blacklist first
    is_blacklisted = check_blacklist(url)
    blacklist_score = 100 if is_blacklisted else 0

    # Calculate ML risk based on predicted label and confidence
    model_prob = label_probs.get(predicted_label, 0)

    # Base risk depends on the predicted threat type
    if predicted_label == "benign":
        # For benign predictions, risk should be very low when confidence is high
        ml_risk = max(5, (1 - model_prob) * 25)  # Risk decreases with higher confidence
    elif predicted_label == "phishingCredential":
        base_ml_risk = 60  # High base risk for phishing
        ml_risk = base_ml_risk + (model_prob * 25)  # Additional risk based on confidence
    elif predicted_label == "malwareSite":
        base_ml_risk = 70  # Very high base risk for malware
        ml_risk = base_ml_risk + (model_prob * 20)  # Additional risk based on confidence
    elif predicted_label == "adFraud":
        base_ml_risk = 40  # Medium base risk for ad fraud
        ml_risk = base_ml_risk + (model_prob * 30)  # Additional risk based on confidence
    elif predicted_label == "financialScam":
        base_ml_risk = 65  # High base risk for financial scams
        ml_risk = base_ml_risk + (model_prob * 25)  # Additional risk based on confidence
    else:
        base_ml_risk = 30  # Default medium risk
        ml_risk = base_ml_risk + (model_prob * 20)

    vt = scan_with_virustotal(url)
    vt_score = min(vt["malicious"] * 10 + vt["suspicious"] * 5, 30)

    domain_info = get_domain_info(url)
    domain = domain_info["domain"] or ""
    ip = domain_info["ip"]

    heuristic = 0
    if len(domain) < 6:
        heuristic += 5
    if "-" in domain:
        heuristic += 5

    geo = ip_to_country(ip)

    total_risk = min(100, round(ml_risk + vt_score + heuristic + blacklist_score, 2))

    if total_risk < 20:
        severity = "Low"
    elif total_risk < 50:
        severity = "Medium"
    elif total_risk < 80:
        severity = "High"
    else:
        severity = "Critical"

    reason_parts = []
    if is_blacklisted:
        reason_parts.append("URL contains known malicious patterns.")
    reason_parts.append(f"Model confidence={model_prob:.2f}.")
    reason_parts.append(f"VT malicious={vt['malicious']} suspicious={vt['suspicious']}.")
    reason_parts.append(f"Heuristic={heuristic}.")

    reason = " ".join(reason_parts)

    geo = None
    if domain_info.get("ip"):
        geo = get_ip_geolocation(domain_info["ip"])

    return {
        "risk_score": total_risk,
        "severity": severity,
        "reason": reason,
        "vt": vt,
        "domain": domain_info,
        "geo": geo   # ← NEW
    }

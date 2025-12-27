import requests

# Test URLs: mix of safe and malicious
test_urls = [
    "https://testsafebrowsing.appspot.com/s/malware.html",  # Known malicious
    "https://www.google.com",  # Safe
    "https://www.microsoft.com",  # Safe
    "https://www.github.com",  # Safe
    "https://malicious-site.com/phishing",  # Potentially malicious
    "https://www.amazon.com",  # Safe
    "https://www.paypal.com",  # Safe
    "https://fake-bank-login.com",  # Potentially malicious
]

def test_url_analysis(url):
    try:
        response = requests.post("http://localhost:8008/analyze", json={"url": url})
        if response.status_code == 200:
            data = response.json()
            print(f"\nURL: {url}")
            print(f"Prediction: {data['prediction']}")
            print(f"Confidence: {data['modelConfidence']:.2f}")
            print(f"Risk Score: {data['riskScore']}")
            print(f"Severity: {data['severity']}")
            print(f"VT Malicious: {data['vt_malicious']}")
            print(f"VT Suspicious: {data['vt_suspicious']}")
        else:
            print(f"Error analyzing {url}: {response.status_code}")
    except Exception as e:
        print(f"Failed to analyze {url}: {e}")

if __name__ == "__main__":
    print("Testing URL analysis for various safe and malicious URLs...")
    for url in test_urls:
        test_url_analysis(url)
    print("\nTesting complete.")

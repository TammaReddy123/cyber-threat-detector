from risk_scoring import compute_risk_score

# Test the malware URL
url = 'https://testsafebrowsing.appspot.com/s/malware.html'
predicted_label = 'benign'  # What the model predicted (corrected label)
label_probs = {'benign': 0.929, 'malicious': 0.071}  # From our test

result = compute_risk_score(url, predicted_label, label_probs)

print(f"URL: {url}")
print(f"Risk Score: {result['risk_score']}")
print(f"Severity: {result['severity']}")
print(f"Reason: {result['reason']}")

# Test a safe URL for comparison
safe_url = 'https://www.google.com'
safe_result = compute_risk_score(safe_url, 'benign', {'benign': 0.95, 'malicious': 0.05})

print(f"\nSafe URL: {safe_url}")
print(f"Risk Score: {safe_result['risk_score']}")
print(f"Severity: {safe_result['severity']}")

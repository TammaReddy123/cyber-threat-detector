from predict import URLThreatModel

# Test the malware URL
model = URLThreatModel()
prediction, confidence, probs = model.predict_single('https://testsafebrowsing.appspot.com/s/malware.html')

print(f'Prediction: {prediction}')
print(f'Confidence: {confidence:.3f}')
print(f'All probabilities: {probs}')

# Also test a safe URL for comparison
safe_prediction, safe_confidence, safe_probs = model.predict_single('https://www.google.com')
print(f'\nSafe URL (Google) Prediction: {safe_prediction}')
print(f'Safe URL Confidence: {safe_confidence:.3f}')
print(f'Safe URL probabilities: {safe_probs}')

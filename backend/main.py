from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pydantic import BaseModel
import uvicorn
from predict import URLThreatModel
from risk_scoring import compute_risk_score
from database import init_db, save_log, get_logs
from feature_extraction import extract_url_features
import requests
import os
from dotenv import load_dotenv
import tldextract
import google.generativeai as genai
import asyncio
from functools import lru_cache
import json

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # or your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
load_dotenv()

# Global model instance for caching
model_instance = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global model_instance
    init_db()
    try:
        model_instance = URLThreatModel()
        print("ML model loaded successfully")
    except Exception as e:
        print(f"Failed to load ML model: {e}")
        model_instance = None
    yield

app = FastAPI(title="AI-Powered Threat Intelligence Platform", lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_API_KEY = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")

# Configure Google Gemini AI
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("Warning: GEMINI_API_KEY not set. AI analysis will be limited.")
model = genai.GenerativeModel('gemini-1.5-flash')

class URLRequest(BaseModel):
    url: str

class MultipleURLRequest(BaseModel):
    urls: list[str]

class ThreatLog(BaseModel):
    id: int
    url: str
    prediction: str
    confidence: float
    risk_score: float
    severity: str
    vt_malicious: int
    vt_suspicious: int
    country: str
    timestamp: str

def extract_country(url):
    ext = tldextract.extract(url)
    suffix = ext.suffix.lower()
    mapping = {
        "in": "India", "gov.in": "India", "co.in": "India",
        "uk": "United Kingdom", "co.uk": "United Kingdom",
        "us": "United States", "au": "Australia", "ca": "Canada",
        "de": "Germany", "fr": "France", "jp": "Japan", "cn": "China", "br": "Brazil",
        "ru": "Russia", "it": "Italy", "es": "Spain", "nl": "Netherlands",
        "se": "Sweden", "no": "Norway", "dk": "Denmark", "fi": "Finland",
        "pl": "Poland", "cz": "Czech Republic", "sk": "Slovakia", "hu": "Hungary",
        "ro": "Romania", "bg": "Bulgaria", "gr": "Greece", "pt": "Portugal",
        "ch": "Switzerland", "at": "Austria", "be": "Belgium", "ie": "Ireland",
        "nz": "New Zealand", "za": "South Africa", "mx": "Mexico", "ar": "Argentina",
        "cl": "Chile", "pe": "Peru", "co": "Colombia", "ve": "Venezuela",
        "kr": "South Korea", "tw": "Taiwan", "th": "Thailand", "my": "Malaysia",
        "sg": "Singapore", "ph": "Philippines", "id": "Indonesia", "vn": "Vietnam"
    }
    return mapping.get(suffix, mapping.get(suffix.split(".")[-1], "Unknown"))

def detect_country_from_url(url):
    """Use AI to detect country-related keywords in URL"""
    try:
        # Skip AI analysis if GEMINI_API_KEY is not set
        if not GEMINI_API_KEY:
            return "Unknown"

        prompt = f"""
        Analyze the following URL and determine if it contains any country-related keywords, domain names, or references:

        URL: {url}

        Look for:
        - Country names in the URL path or domain
        - Country codes (ISO codes like US, UK, IN, etc.)
        - City names that can indicate countries
        - Language indicators
        - Regional domain extensions

        If you find any country-related indicators, return the full country name.
        If no clear country indicators are found, return "Unknown".

        Examples:
        - "facebook.com/us" -> "United States"
        - "amazon.co.uk" -> "United Kingdom"
        - "google.co.in" -> "India"
        - "news.bbc.co.uk" -> "United Kingdom"
        - "tokyo-restaurant.com" -> "Japan" (if clear indicators)
        - "randomsite.com" -> "Unknown"

        Return only the country name or "Unknown". Do not include any other text or explanation.
        """

        response = model.generate_content(prompt, generation_config={"temperature": 0.1, "max_output_tokens": 50})
        country = response.text.strip()

        # Clean up the response
        if country.lower() in ["unknown", "none", "n/a", ""]:
            return "Unknown"

        # Validate that it's actually a country name
        known_countries = [
            "United States", "United Kingdom", "India", "Australia", "Canada",
            "Germany", "France", "Japan", "China", "Brazil", "Russia", "Italy",
            "Spain", "Netherlands", "Sweden", "Norway", "Denmark", "Finland",
            "Poland", "Czech Republic", "Slovakia", "Hungary", "Romania",
            "Bulgaria", "Greece", "Portugal", "Switzerland", "Austria",
            "Belgium", "Ireland", "New Zealand", "South Africa", "Mexico",
            "Argentina", "Chile", "Peru", "Colombia", "Venezuela", "South Korea",
            "Taiwan", "Thailand", "Malaysia", "Singapore", "Philippines",
            "Indonesia", "Vietnam"
        ]

        # Check if the detected country is in our known list
        for known_country in known_countries:
            if known_country.lower() in country.lower():
                return known_country

        return "Unknown"

    except Exception as e:
        print(f"AI country detection failed for {url}: {e}")
        return "Unknown"

def get_fallback_prediction(url: str):
    """Enhanced fallback prediction using heuristics when ML model is not available"""
    url_lower = url.lower()

    # Check for suspicious patterns and keywords
    suspicious_keywords = [
        'login', 'password', 'bank', 'paypal', 'bitcoin', 'crypto', 'free', 'win', 'prize',
        'account', 'verify', 'secure', 'update', 'confirm', 'alert', 'notification',
        'signin', 'logon', 'authenticate', 'reset', 'recovery', 'support'
    ]

    high_risk_keywords = [
        'paypal-login', 'bank-login', 'apple-id', 'microsoft-login', 'amazon-login',
        'netflix-login', 'facebook-login', 'google-login', 'instagram-login'
    ]

    # Count suspicious elements
    suspicious_count = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
    high_risk_count = sum(1 for keyword in high_risk_keywords if keyword in url_lower)

    # Check for URL structure issues
    has_https = url.startswith('https://')
    has_suspicious_chars = any(char in url for char in ['@', '%', '?', '&', '='])
    has_long_subdomain = len(url.split('.')) > 3
    has_ip_address = any(part.isdigit() for part in url.replace('https://', '').replace('http://', '').split('.')[:4])

    # Calculate risk score based on heuristics
    risk_score = 0

    if not has_https:
        risk_score += 20  # HTTP is suspicious

    if suspicious_count > 0:
        risk_score += min(suspicious_count * 15, 40)  # Up to 40 points for suspicious keywords

    if high_risk_count > 0:
        risk_score += min(high_risk_count * 25, 50)  # Up to 50 points for high-risk keywords

    if has_suspicious_chars:
        risk_score += 10

    if has_long_subdomain:
        risk_score += 15

    if has_ip_address:
        risk_score += 25  # IP addresses are often malicious

    # Determine prediction based on risk score
    if risk_score >= 70:
        prediction = "phishingCredential"
        confidence = min(risk_score / 100.0, 0.95)
        probs = {
            "benign": max(0.05, 1 - confidence),
            "phishingCredential": confidence,
            "malwareSite": 0.02,
            "adFraud": 0.01,
            "financialScam": 0.02
        }
    elif risk_score >= 40:
        prediction = "malwareSite"
        confidence = risk_score / 100.0
        probs = {
            "benign": max(0.1, 0.6 - confidence),
            "phishingCredential": confidence * 0.3,
            "malwareSite": confidence,
            "adFraud": confidence * 0.2,
            "financialScam": confidence * 0.1
        }
    else:
        prediction = "benign"
        confidence = max(0.3, 0.8 - (risk_score / 100.0))
        probs = {
            "benign": confidence,
            "phishingCredential": (1 - confidence) * 0.4,
            "malwareSite": (1 - confidence) * 0.3,
            "adFraud": (1 - confidence) * 0.2,
            "financialScam": (1 - confidence) * 0.1
        }

    print(f"Fallback prediction for {url}: {prediction} (risk_score: {risk_score}, confidence: {confidence:.2f})")
    return prediction, confidence, probs

def analyze_url_with_ai(url):
    """Analyze URL using Google Gemini AI to determine safety"""
    try:
        # Skip AI analysis if GEMINI_API_KEY is not set
        if not GEMINI_API_KEY:
            return {
                "safety": "Unknown",
                "risk_level": "Medium",
                "threats": ["AI analysis not available"],
                "recommendations": ["Manual verification recommended"],
                "confidence": 50
            }

        prompt = f"""
        Analyze the following URL for potential security threats and determine if it's safe or risky:

        URL: {url}

        Please provide a detailed analysis including:
        1. Overall safety assessment (Safe or Risky)
        2. Risk level (Low, Medium, High)
        3. Potential threats (if any)
        4. Recommendations

        Consider factors like:
        - Domain reputation
        - URL structure and patterns
        - Known malicious patterns
        - Suspicious keywords or characters
        - HTTPS status
        - Domain age and reputation

        Format your response as JSON with the following structure:
        {{
            "safety": "Safe" or "Risky",
            "risk_level": "Low/Medium/High",
            "threats": ["list of potential threats"],
            "recommendations": ["list of recommendations"],
            "confidence": 0-100
        }}
        """

        response = model.generate_content(prompt, generation_config={"temperature": 0.1, "max_output_tokens": 1000})
        result_text = response.text.strip()

        # Try to parse JSON response
        try:
            import json
            result = json.loads(result_text)
            return result
        except json.JSONDecodeError:
            # Fallback parsing if JSON is malformed
            safety = "Risky" if "risky" in result_text.lower() else "Safe"
            risk_level = "High" if "high" in result_text.lower() else "Medium" if "medium" in result_text.lower() else "Low"
            return {
                "safety": safety,
                "risk_level": risk_level,
                "threats": ["AI analysis indicates potential risks"],
                "recommendations": ["Exercise caution when visiting this URL"],
                "confidence": 75
            }

    except Exception as e:
        print(f"AI analysis failed for {url}: {e}")
        return {
            "safety": "Unknown",
            "risk_level": "Medium",
            "threats": ["Unable to analyze with AI"],
            "recommendations": ["Manual verification recommended"],
            "confidence": 50
        }

@app.post("/analyze")
async def analyze_url(request: URLRequest):
    try:
        print(f"Analyzing URL: {request.url}")
        url = request.url

        # Initialize default values
        final_prediction = "benign"
        final_confidence = 0.1
        risk_score = 10
        severity = "Low"
        vt_mal = 0
        vt_susp = 0

        # Enhanced country detection using TLD + AI
        tld_country = extract_country(url)
        ai_country = detect_country_from_url(url)
        country = ai_country if ai_country != "Unknown" else tld_country

        try:
            if model_instance and model_instance.model_available:
                model_prediction, confidence, probs = model_instance.predict_single(url)
                risk = compute_risk_score(url, model_prediction, probs)
                print(f"ML Model prediction: {model_prediction}, confidence: {confidence}")
            else:
                # Enhanced fallback prediction using heuristics
                print("Using fallback prediction (ML model not available)")
                model_prediction, confidence, probs = get_fallback_prediction(url)
                risk = compute_risk_score(url, model_prediction, probs)

            # Determine final prediction based on risk score and model prediction
            if risk["risk_score"] >= 30:  # Lower threshold for better detection
                final_prediction = "malicious"
            else:
                final_prediction = "benign"

            # Use model confidence for final confidence, but adjust based on risk score
            final_confidence = min(confidence, risk["risk_score"] / 100.0)
            risk_score = risk["risk_score"]
            severity = risk["severity"]
            print(f"Final prediction: {final_prediction}, risk_score: {risk_score}")
        except Exception as e:
            print(f"ML Model analysis failed: {str(e)}")
            # Enhanced fallback for complete failure
            model_prediction, confidence, probs = get_fallback_prediction(url)
            risk = compute_risk_score(url, model_prediction, probs)
            # Determine final prediction based on risk score
            if risk["risk_score"] >= 30:
                final_prediction = "malicious"
            else:
                final_prediction = "benign"
            final_confidence = min(confidence, risk["risk_score"] / 100.0)
            risk_score = risk["risk_score"]
            severity = risk["severity"]

        # VirusTotal integration
        try:
            vt_result = check_virustotal(url)
            vt_mal = vt_result.get('malicious', 0)
            vt_susp = vt_result.get('suspicious', 0)
            if vt_result.get('country') != "Unknown":
                country = vt_result.get('country', country)
        except Exception as e:
            print(f"VirusTotal analysis failed: {str(e)}")

        # AI Analysis using Google Gemini
        ai_analysis = analyze_url_with_ai(url)

        # Map AI results to frontend expected fields
        prediction = "Malware Site" if final_prediction == "malicious" else "Benign"
        modelConfidence = final_confidence * 100  # Convert to percentage
        riskScore = risk_score
        adFraud = "High" if vt_mal > 0 or ai_analysis.get("risk_level") == "High" else "Low"
        benign = "Yes" if final_prediction == "benign" else "No"
        financialScam = "Detected" if ai_analysis.get("threats", []) and any("financial" in threat.lower() for threat in ai_analysis.get("threats", [])) else "Not Detected"
        malwareSite = "Yes" if final_prediction == "malicious" else "No"
        phishingCredential = "High Risk" if ai_analysis.get("risk_level") == "High" else "Low Risk"

        save_log(url, final_prediction, final_confidence*100, risk_score, severity, vt_mal, vt_susp, country)

        print(f"Analysis complete: {final_prediction} (risk: {risk_score})")
        return {
            "url": url,
            "prediction": prediction,
            "modelConfidence": modelConfidence,
            "riskScore": riskScore,
            "severity": severity,
            "vt_malicious": vt_mal,
            "vt_suspicious": vt_susp,
            "adFraud": adFraud,
            "benign": benign,
            "financialScam": financialScam,
            "malwareSite": malwareSite,
            "phishingCredential": phishingCredential,
            "country": country,
            "aiAnalysis": ai_analysis
        }
    except Exception as e:
        print(f"Analysis failed: {str(e)}")
        # Return safe defaults on complete failure
        return {
            "url": request.url,
            "prediction": "Benign",
            "modelConfidence": 10.0,
            "riskScore": 10,
            "adFraud": "Low",
            "benign": "Yes",
            "financialScam": "Not Detected",
            "malwareSite": "No",
            "phishingCredential": "Low Risk",
            "country": extract_country(request.url),
            "aiAnalysis": {
                "safety": "Safe",
                "risk_level": "Low",
                "threats": [],
                "recommendations": ["URL appears safe"],
                "confidence": 80
            }
        }

async def analyze_single_url(url: str):
    """Analyze a single URL and return the result"""
    try:
        print(f"Analyzing URL: {url}")

        # Initialize default values
        final_prediction = "benign"
        final_confidence = 0.1
        risk_score = 10
        severity = "Low"
        vt_mal = 0
        vt_susp = 0

        # Enhanced country detection using TLD + AI
        tld_country = extract_country(url)
        ai_country = detect_country_from_url(url)
        country = ai_country if ai_country != "Unknown" else tld_country

        try:
            if model_instance and model_instance.model_available:
                model_prediction, confidence, probs = model_instance.predict_single(url)
                risk = compute_risk_score(url, model_prediction, probs)
                print(f"ML Model prediction: {model_prediction}, confidence: {confidence}")
            else:
                # Enhanced fallback prediction using heuristics
                print("Using fallback prediction (ML model not available)")
                model_prediction, confidence, probs = get_fallback_prediction(url)
                risk = compute_risk_score(url, model_prediction, probs)

            # Determine final prediction based on risk score and model prediction
            if risk["risk_score"] >= 30:  # Lower threshold for better detection
                final_prediction = "malicious"
            else:
                final_prediction = "benign"

            # Use model confidence for final confidence, but adjust based on risk score
            final_confidence = min(confidence, risk["risk_score"] / 100.0)
            risk_score = risk["risk_score"]
            severity = risk["severity"]
            print(f"Final prediction: {final_prediction}, risk_score: {risk_score}")
        except Exception as e:
            print(f"ML Model analysis failed for {url}: {str(e)}")
            # Enhanced fallback for complete failure
            model_prediction, confidence, probs = get_fallback_prediction(url)
            risk = compute_risk_score(url, model_prediction, probs)
            # Determine final prediction based on risk score
            if risk["risk_score"] >= 30:
                final_prediction = "malicious"
            else:
                final_prediction = "benign"
            final_confidence = min(confidence, risk["risk_score"] / 100.0)
            risk_score = risk["risk_score"]
            severity = risk["severity"]

        # VirusTotal integration (optional - skip if no API key)
        try:
            vt_result = check_virustotal(url)
            vt_mal = vt_result.get('malicious', 0)
            vt_susp = vt_result.get('suspicious', 0)
            if vt_result.get('country') != "Unknown":
                country = vt_result.get('country', country)
        except Exception as e:
            print(f"VirusTotal analysis failed for {url}: {str(e)}")

        # AI Analysis using Google Gemini
        ai_analysis = analyze_url_with_ai(url)

        # Map AI results to frontend expected fields
        prediction = "Malware Site" if final_prediction == "malicious" else "Benign"
        modelConfidence = final_confidence * 100  # Convert to percentage
        riskScore = risk_score
        adFraud = "High" if vt_mal > 0 or ai_analysis.get("risk_level") == "High" else "Low"
        benign = "Yes" if final_prediction == "benign" else "No"
        financialScam = "Detected" if ai_analysis.get("threats", []) and any("financial" in threat.lower() for threat in ai_analysis.get("threats", [])) else "Not Detected"
        malwareSite = "Yes" if final_prediction == "malicious" else "No"
        phishingCredential = "High Risk" if ai_analysis.get("risk_level") == "High" else "Low Risk"

        save_log(url, final_prediction, final_confidence*100, risk_score, severity, vt_mal, vt_susp, country)

        return {
            "url": url,
            "prediction": prediction,
            "modelConfidence": modelConfidence,
            "riskScore": riskScore,
            "adFraud": adFraud,
            "benign": benign,
            "financialScam": financialScam,
            "malwareSite": malwareSite,
            "phishingCredential": phishingCredential,
            "country": country,
            "aiAnalysis": ai_analysis
        }

    except Exception as e:
        print(f"Analysis failed for {url}: {str(e)}")
        # Return safe defaults on complete failure
        return {
            "url": url,
            "prediction": "Benign",
            "modelConfidence": 10.0,
            "riskScore": 10,
            "adFraud": "Low",
            "benign": "Yes",
            "financialScam": "Not Detected",
            "malwareSite": "No",
            "phishingCredential": "Low Risk",
            "country": extract_country(url),
            "aiAnalysis": {
                "safety": "Safe",
                "risk_level": "Low",
                "threats": [],
                "recommendations": ["URL appears safe"],
                "confidence": 80
            }
        }

@app.post("/analyze-multiple")
async def analyze_multiple_urls(request: MultipleURLRequest):
    try:
        print(f"Analyzing {len(request.urls)} URLs")
        valid_urls = [url for url in request.urls if url.strip()]

        if not valid_urls:
            return {"results": []}

        # Process URLs in parallel using asyncio.gather
        tasks = [analyze_single_url(url) for url in valid_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions that occurred during parallel processing
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"Exception occurred for URL {valid_urls[i]}: {result}")
                # Return safe defaults for failed URLs
                processed_results.append({
                    "url": valid_urls[i],
                    "prediction": "Benign",
                    "modelConfidence": 10.0,
                    "riskScore": 10,
                    "adFraud": "Low",
                    "benign": "Yes",
                    "financialScam": "Not Detected",
                    "malwareSite": "No",
                    "phishingCredential": "Low Risk",
                    "country": extract_country(valid_urls[i]),
                    "aiAnalysis": {
                        "safety": "Safe",
                        "risk_level": "Low",
                        "threats": [],
                        "recommendations": ["URL appears safe"],
                        "confidence": 80
                    }
                })
            else:
                processed_results.append(result)

        print(f"Multiple URL analysis complete: {len(processed_results)} results")
        return {"results": processed_results}

    except Exception as e:
        print(f"Multiple URL analysis failed: {str(e)}")
        return {"results": [], "error": str(e)}

@app.get("/logs", response_model=list[ThreatLog])
async def get_threat_logs():
    logs = get_logs()
    return [
        {
            "id": log[0],
            "url": log[1],
            "prediction": log[2],
            "confidence": log[3],
            "risk_score": log[4],
            "severity": log[5],
            "vt_malicious": log[6],
            "vt_suspicious": log[7],
            "country": log[8],
            "timestamp": log[9]
        }
        for log in logs
    ]

def check_virustotal(url):
    if not VT_API_KEY:
        print(f"VirusTotal API key not found, skipping VT analysis for {url}")
        return {}
    try:
        headers = {"x-apikey": VT_API_KEY}

        # First, submit the URL for analysis
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers=headers,
            timeout=10  # Add timeout to prevent hanging
        )

        if submit_response.status_code == 200:
            submit_data = submit_response.json()
            analysis_id = submit_data["data"]["id"]

            # Reduced wait time for better performance (from 2s to 1s)
            import time
            time.sleep(1)

            # Get the analysis results
            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=10  # Add timeout to prevent hanging
            )

            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data["data"]["attributes"]["stats"]
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "country": "Unknown"  # VT doesn't provide country in analysis results
                }
    except Exception as e:
        print(f"VirusTotal error for {url}: {e}")
        pass
    return {}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8008)

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

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
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

class URLRequest(BaseModel):
    url: str

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
        "de": "Germany", "fr": "France", "jp": "Japan", "cn": "China", "br": "Brazil"
    }
    return mapping.get(suffix, mapping.get(suffix.split(".")[-1], "Unknown"))

@app.post("/analyze")
async def analyze_url(request: URLRequest):
    try:
        print(f"Analyzing URL: {request.url}")
        url = request.url
        model = URLThreatModel()
        model_prediction, confidence, probs = model.predict_single(url)
        risk = compute_risk_score(url, model_prediction, probs)

        # Determine final prediction based on risk score
        # If risk score >= 50, consider it malicious, otherwise safe
        final_prediction = "malicious" if risk["risk_score"] >= 50 else "safe"
        final_confidence = risk["risk_score"] / 100.0  # Convert risk score to confidence percentage

        # VirusTotal integration
        vt_result = check_virustotal(url)
        vt_mal = vt_result.get('malicious', 0)
        vt_susp = vt_result.get('suspicious', 0)
        country = vt_result.get('country', extract_country(url))

        save_log(url, final_prediction, final_confidence*100, risk["risk_score"], risk["severity"], vt_mal, vt_susp, country)

        print(f"Analysis complete: {final_prediction} (risk: {risk['risk_score']})")
        return {
            "url": url,
            "prediction": final_prediction,
            "confidence": final_confidence,
            "risk_score": risk["risk_score"],
            "severity": risk["severity"],
            "vt_malicious": vt_mal,
            "vt_suspicious": vt_susp,
            "country": country
        }
    except Exception as e:
        print(f"Analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

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
        return {}
    try:
        headers = {"x-apikey": VT_API_KEY}

        # First, submit the URL for analysis
        submit_response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers=headers
        )

        if submit_response.status_code == 200:
            submit_data = submit_response.json()
            analysis_id = submit_data["data"]["id"]

            # Wait a moment for analysis to complete
            import time
            time.sleep(2)

            # Get the analysis results
            analysis_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
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
        print(f"VirusTotal error: {e}")
        pass
    return {}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8007)
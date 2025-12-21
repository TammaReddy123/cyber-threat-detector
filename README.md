# AI-Powered Threat Intelligence Platform

This project is an AI-powered threat intelligence platform built with Python, FastAPI, Machine Learning, VirusTotal, React, WebGL (Three.js), and SQLite.

## Features

- Detect phishing and malicious URLs using ML and threat intelligence
- Integrate VirusTotal for real-time threat analysis
- Heuristic scoring for risk severity computation
- FastAPI backend for scalable threat ingestion and logging
- Interactive threat dashboard with real-time global attack visualization
- Country-based attribution, analytics, and live attack feeds

## Setup

### Backend

1. Navigate to the backend directory:
   ```
   cd backend
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   Create a `.env` file with your VirusTotal API key:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

4. Run the FastAPI server:
   ```
   python main.py
   ```

### Frontend

1. Navigate to the frontend directory:
   ```
   cd frontend
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Start the React app:
   ```
   npm start
   ```

## Usage

- Access the frontend at `http://localhost:3000`
- Enter a URL to analyze in the input field
- View analysis results and threat logs
- Visualize threats on the 3D globe

## API Endpoints

- `POST /analyze`: Analyze a URL for threats
- `GET /logs`: Retrieve threat logs
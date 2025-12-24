@echo off
echo Starting Cyber Threat Detector...

REM Start backend in background
start "Backend" cmd /c "venv\Scripts\python -m uvicorn backend.main:app --host 0.0.0.0 --port 8008 --reload"

REM Wait a bit for backend to start
timeout /t 5 /nobreak > nul

REM Start frontend
cd frontend
npm start

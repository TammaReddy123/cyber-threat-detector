import React, { useState, useEffect } from 'react';
import Dashboard from './components/Dashboard';
import Globe from './components/Globe';
import ThreatLogs from './components/ThreatLogs';

function App() {
  const [logs, setLogs] = useState([]);
  const [systemStatus, setSystemStatus] = useState('Initializing...');
  const [currentView, setCurrentView] = useState('scanner');

  useEffect(() => {
    const statuses = [
      'Initializing...',
      'Loading AI models...',
      'Connecting to databases...',
      'System Online'
    ];
    let index = 0;
    const interval = setInterval(() => {
      setSystemStatus(statuses[index]);
      index = (index + 1) % statuses.length;
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleAnalyze = async (url) => {
    // API call to backend
    const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8008';
    const response = await fetch(`${backendUrl}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const result = await response.json();

    // Use the result structure from backend
    const enhancedResult = {
      url: result.url,
      prediction: result.prediction,
      modelConfidence: result.modelConfidence,
      riskScore: result.riskScore,
      adFraud: result.adFraud,
      benign: result.benign,
      financialScam: result.financialScam,
      malwareSite: result.malwareSite,
      phishingCredential: result.phishingCredential,
      country: result.country || 'Unknown',
      aiAnalysis: result.aiAnalysis
    };

    setLogs([...logs, enhancedResult]);
    return enhancedResult;
  };

  const handleMultipleAnalyze = (results) => {
    const enhancedResults = results.map(result => ({
      url: result.url,
      prediction: result.prediction,
      modelConfidence: result.modelConfidence,
      riskScore: result.riskScore,
      adFraud: result.adFraud,
      benign: result.benign,
      financialScam: result.financialScam,
      malwareSite: result.malwareSite,
      phishingCredential: result.phishingCredential,
      country: result.country || 'Unknown',
      aiAnalysis: result.aiAnalysis
    }));
    setLogs([...logs, ...enhancedResults]);
  };

  const renderView = () => {
    switch (currentView) {
      case 'scanner':
        return <Dashboard onAnalyze={handleAnalyze} onMultipleAnalyze={handleMultipleAnalyze} />;
      case 'analytics':
        return <ThreatLogs logs={logs} />;
      case 'map':
        return <Globe logs={logs} />;
      default:
        return <Dashboard onAnalyze={handleAnalyze} onMultipleAnalyze={handleMultipleAnalyze} />;
    }
  };

  return (
    <div className="App">
      <h1 style={{ color: '#00ff00', textShadow: '0 0 10px #00ff00', animation: 'glow 2s ease-in-out infinite alternate' }}>
        AI-Powered Threat Intelligence Platform
      </h1>
      <div style={{ color: '#ffff00', marginBottom: '20px', animation: 'blink 1s infinite' }}>
        Status: {systemStatus}
      </div>
      <nav className="nav-tabs">
        <button
          className={`nav-tab ${currentView === 'scanner' ? 'active' : ''}`}
          onClick={() => setCurrentView('scanner')}
        >
          URL Scanner
        </button>
        <button
          className={`nav-tab ${currentView === 'analytics' ? 'active' : ''}`}
          onClick={() => setCurrentView('analytics')}
        >
          Analytics Dashboard
        </button>
        <button
          className={`nav-tab ${currentView === 'map' ? 'active' : ''}`}
          onClick={() => setCurrentView('map')}
        >
          Global Threat Map
        </button>
      </nav>
      {renderView()}
    </div>
  );
}

export default App;

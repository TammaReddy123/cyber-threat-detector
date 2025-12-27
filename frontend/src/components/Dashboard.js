import React, { useState } from 'react';
import { Pie, Line } from 'react-chartjs-2';
import SecurityAlert from './SecurityAlert';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
} from 'chart.js';

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title
);

function Dashboard({ onAnalyze, onMultipleAnalyze }) {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [currentResult, setCurrentResult] = useState(null);
  const [multipleUrls, setMultipleUrls] = useState('');
  const [isMultipleScanning, setIsMultipleScanning] = useState(false);
  const [multipleResults, setMultipleResults] = useState([]);
  const [securityAlert, setSecurityAlert] = useState({ isVisible: false, url: '', riskScore: 0, prediction: '' });

  // Download functions
  const downloadSingleResult = () => {
    if (!currentResult) return;

    const dataStr = JSON.stringify(currentResult, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);

    const exportFileDefaultName = `threat-analysis-${currentResult.url.replace(/[^a-zA-Z0-9]/g, '_')}-${new Date().toISOString().split('T')[0]}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const downloadMultipleResults = () => {
    if (multipleResults.length === 0) return;

    const data = {
      scanDate: new Date().toISOString(),
      totalUrls: multipleResults.length,
      results: multipleResults
    };

    const dataStr = JSON.stringify(data, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);

    const exportFileDefaultName = `threat-analysis-multiple-${new Date().toISOString().split('T')[0]}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (url) {
      setIsScanning(true);
      setCurrentResult(null);
      try {
        const result = await onAnalyze(url);
        setCurrentResult(result);

        // Show security alert for malicious URLs (adjusted threshold to match backend)
        if (result.prediction === 'Malware Site' || result.riskScore > 30) {
          setSecurityAlert({
            isVisible: true,
            url: result.url,
            riskScore: result.riskScore,
            prediction: result.prediction
          });
        }
      } catch (error) {
        console.error('Analysis failed:', error);
        setCurrentResult({
          url,
          prediction: 'Error',
          modelConfidence: 0,
          riskScore: 0,
          adFraud: 'Unknown',
          benign: 'Unknown',
          financialScam: 'Unknown',
          malwareSite: 'Unknown',
          phishingCredential: 'Unknown',
          country: 'Unknown',
          aiAnalysis: { safety: 'Unknown', risk_level: 'Unknown', threats: ['Analysis failed'], recommendations: ['Try again later'], confidence: 0 }
        });
      }
      setIsScanning(false);
      setUrl('');
    }
  };

  const handleMultipleSubmit = async (e) => {
    e.preventDefault();
    if (multipleUrls.trim()) {
      setIsMultipleScanning(true);
      setMultipleResults([]);
      try {
        const urls = multipleUrls.split('\n').map(url => url.trim()).filter(url => url);
        const response = await fetch(`${process.env.REACT_APP_BACKEND_URL}/analyze-multiple`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ urls }),
        });
        const data = await response.json();
        setMultipleResults(data.results || []);
        if (onMultipleAnalyze && data.results) {
          onMultipleAnalyze(data.results);
        }

        // Show security alerts for malicious URLs in multiple results
        const maliciousResults = data.results.filter(result =>
          result.prediction === 'Malware Site' || result.riskScore > 50
        );
        if (maliciousResults.length > 0) {
          // Show alert for the first malicious URL found
          const firstMalicious = maliciousResults[0];
          setSecurityAlert({
            isVisible: true,
            url: firstMalicious.url,
            riskScore: firstMalicious.riskScore,
            prediction: firstMalicious.prediction
          });
        }
      } catch (error) {
        console.error('Multiple analysis failed:', error);
        setMultipleResults([]);
      }
      setIsMultipleScanning(false);
      setMultipleUrls('');
    }
  };

  return (
    <div className="dashboard">
      <h2 style={{ color: '#00ff00', textShadow: '0 0 10px #00ff00', animation: 'glow 2s ease-in-out infinite alternate' }}>
        Threat Analysis Dashboard
      </h2>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter URL to analyze"
          required
          style={{ animation: isScanning ? 'pulse 1s infinite' : 'none' }}
        />
        <button type="submit" disabled={isScanning}>
          {isScanning ? 'Scanning...' : 'Analyze'}
        </button>
      </form>
      {isScanning && (
        <div style={{ marginTop: '10px', color: '#ffff00', animation: 'blink 1s infinite' }}>
          Scanning in progress...
        </div>
      )}

      {/* Multiple URL Scanning Section */}
      <div style={{ marginTop: '40px', padding: '20px', border: '2px solid #00ff00', borderRadius: '10px', background: 'rgba(0, 0, 0, 0.8)' }}>
        <h3 style={{ color: '#00ff00', textShadow: '0 0 10px #00ff00', marginBottom: '15px' }}>
          Multiple URL Scanning
        </h3>
        <form onSubmit={handleMultipleSubmit}>
          <textarea
            value={multipleUrls}
            onChange={(e) => setMultipleUrls(e.target.value)}
            placeholder="Enter multiple URLs (one per line) to analyze simultaneously"
            rows="6"
            style={{
              width: '100%',
              padding: '10px',
              background: 'rgba(0, 0, 0, 0.8)',
              border: '1px solid #00ff00',
              borderRadius: '5px',
              color: '#00ff00',
              fontFamily: 'monospace',
              animation: isMultipleScanning ? 'pulse 1s infinite' : 'none'
            }}
            required
          />
          <button
            type="submit"
            disabled={isMultipleScanning}
            style={{
              marginTop: '10px',
              padding: '10px 20px',
              background: '#00ff00',
              color: '#000',
              border: 'none',
              borderRadius: '5px',
              cursor: 'pointer',
              fontWeight: 'bold'
            }}
          >
            {isMultipleScanning ? 'Scanning Multiple URLs...' : 'Scan Multiple URLs'}
          </button>
        </form>
        {isMultipleScanning && (
          <div style={{ marginTop: '10px', color: '#ffff00', animation: 'blink 1s infinite' }}>
            Scanning multiple URLs in progress...
          </div>
        )}
      </div>

      {/* Multiple Results Display */}
      {multipleResults.length > 0 && (
        <div className="multiple-results" style={{ marginTop: '20px', padding: '20px', border: '2px solid #00ff00', borderRadius: '10px', background: 'rgba(0, 0, 0, 0.8)', animation: 'fadeIn 0.5s ease-in' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
            <h3 style={{ color: '#00ff00', textShadow: '0 0 10px #00ff00', margin: 0 }}>
              Multiple URL Analysis Results ({multipleResults.length} URLs)
            </h3>
            <button
              onClick={downloadMultipleResults}
              style={{
                padding: '8px 16px',
                background: '#00ff00',
                color: '#000',
                border: 'none',
                borderRadius: '5px',
                cursor: 'pointer',
                fontWeight: 'bold',
                fontSize: '14px'
              }}
            >
              📥 Download All Results
            </button>
          </div>
          <div style={{ display: 'grid', gap: '15px' }}>
            {multipleResults.map((result, index) => (
              <div key={index} style={{ padding: '15px', border: '1px solid #00ff00', borderRadius: '8px', background: 'rgba(0, 0, 0, 0.6)' }}>
                <h4 style={{ color: '#00ff00', marginBottom: '10px', fontSize: '16px' }}>
                  {index + 1}. {result.url}
                </h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '8px' }}>
                  <div className="result-item">
                    <strong>Prediction:</strong> <span style={{ color: result.prediction === 'Benign' ? '#00ff00' : '#ff0000' }}>{result.prediction}</span>
                  </div>
                  <div className="result-item">
                    <strong>Risk Score:</strong> <span style={{ color: result.riskScore > 30 ? '#ff0000' : '#00ff00' }}>{result.riskScore}/100</span>
                  </div>
                  <div className="result-item">
                    <strong>Confidence:</strong> <span style={{ color: '#ffff00' }}>{result.modelConfidence.toFixed(1)}%</span>
                  </div>
                  <div className="result-item">
                    <strong>Malware:</strong> <span style={{ color: result.malwareSite === 'Yes' ? '#ff0000' : '#00ff00' }}>{result.malwareSite}</span>
                  </div>
                  <div className="result-item">
                    <strong>Phishing:</strong> <span style={{ color: result.phishingCredential === 'High Risk' ? '#ff0000' : '#00ff00' }}>{result.phishingCredential}</span>
                  </div>
                  <div className="result-item">
                    <strong>Country:</strong> <span style={{ color: '#ffff00' }}>{result.country}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {currentResult && (
        <div className="analysis-results" style={{ marginTop: '20px', padding: '20px', border: '2px solid #00ff00', borderRadius: '10px', background: 'rgba(0, 0, 0, 0.8)', animation: 'fadeIn 0.5s ease-in' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
            <h3 style={{ color: '#00ff00', textShadow: '0 0 10px #00ff00', margin: 0 }}>Analysis Results for: {currentResult.url}</h3>
            <button
              onClick={downloadSingleResult}
              style={{
                padding: '8px 16px',
                background: '#00ff00',
                color: '#000',
                border: 'none',
                borderRadius: '5px',
                cursor: 'pointer',
                fontWeight: 'bold',
                fontSize: '14px'
              }}
            >
              📥 Download Results
            </button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px', marginTop: '15px' }}>
            <div className="result-item">
              <strong>Prediction:</strong> <span style={{ color: currentResult.prediction === 'Benign' ? '#00ff00' : '#ff0000' }}>{currentResult.prediction}</span>
            </div>
            <div className="result-item">
              <strong>Model Confidence:</strong> <span style={{ color: '#ffff00' }}>{currentResult.modelConfidence.toFixed(2)}%</span>
            </div>
            <div className="result-item">
              <strong>Risk Score:</strong> <span style={{ color: currentResult.riskScore > 50 ? '#ff0000' : '#00ff00' }}>{currentResult.riskScore}/100</span>
            </div>
            <div className="result-item">
              <strong>Ad Fraud:</strong> <span style={{ color: currentResult.adFraud === 'High' ? '#ff0000' : '#00ff00' }}>{currentResult.adFraud}</span>
            </div>
            <div className="result-item">
              <strong>Benign:</strong> <span style={{ color: currentResult.benign === 'Yes' ? '#00ff00' : '#ff0000' }}>{currentResult.benign}</span>
            </div>
            <div className="result-item">
              <strong>Financial Scam:</strong> <span style={{ color: currentResult.financialScam === 'Detected' ? '#ff0000' : '#00ff00' }}>{currentResult.financialScam}</span>
            </div>
            <div className="result-item">
              <strong>Malware Site:</strong> <span style={{ color: currentResult.malwareSite === 'Yes' ? '#ff0000' : '#00ff00' }}>{currentResult.malwareSite}</span>
            </div>
            <div className="result-item">
              <strong>Phishing Credential:</strong> <span style={{ color: currentResult.phishingCredential === 'High Risk' ? '#ff0000' : '#00ff00' }}>{currentResult.phishingCredential}</span>
            </div>
          </div>

          {/* Charts Section */}
          <div style={{ marginTop: '30px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' }}>
            {/* Pie Chart for Threat Categories */}
            <div className="chart-container">
              <h4>Threat Category Distribution</h4>
              <Pie
                data={{
                  labels: ['Ad Fraud', 'Benign', 'Financial Scam', 'Malware Site', 'Phishing Credential'],
                  datasets: [{
                    data: [
                      currentResult.adFraud === 'High' ? 100 : 0,
                      currentResult.benign === 'Yes' ? 100 : 0,
                      currentResult.financialScam === 'Detected' ? 100 : 0,
                      currentResult.malwareSite === 'Yes' ? 100 : 0,
                      currentResult.phishingCredential === 'High Risk' ? 100 : 0
                    ],
                    backgroundColor: [
                      '#ff6384',
                      '#36a2eb',
                      '#cc65fe',
                      '#ffce56',
                      '#ff9f40'
                    ],
                    borderColor: '#00ff00',
                    borderWidth: 2,
                  }]
                }}
                options={{
                  responsive: true,
                  plugins: {
                    legend: {
                      labels: {
                        color: '#00ff00',
                        font: {
                          size: 12
                        }
                      }
                    }
                  }
                }}
              />
            </div>

            {/* Line Chart for Risk Score */}
            <div className="chart-container">
              <h4>Risk Score Trend</h4>
              <Line
                data={{
                  labels: ['Current Analysis'],
                  datasets: [{
                    label: 'Risk Score',
                    data: [currentResult.riskScore],
                    borderColor: '#00ff00',
                    backgroundColor: 'rgba(0, 255, 0, 0.1)',
                    borderWidth: 3,
                    pointBackgroundColor: '#00ff00',
                    pointBorderColor: '#00ff00',
                    pointRadius: 8,
                    pointHoverRadius: 12,
                    fill: true,
                  }]
                }}
                options={{
                  responsive: true,
                  plugins: {
                    legend: {
                      labels: {
                        color: '#00ff00',
                        font: {
                          size: 12
                        }
                      }
                    }
                  },
                  scales: {
                    x: {
                      grid: {
                        color: 'rgba(0, 255, 0, 0.2)',
                        borderColor: '#00ff00'
                      },
                      ticks: {
                        color: '#00ff00'
                      }
                    },
                    y: {
                      grid: {
                        color: 'rgba(0, 255, 0, 0.2)',
                        borderColor: '#00ff00'
                      },
                      ticks: {
                        color: '#00ff00',
                        callback: function(value) {
                          return value + '%';
                        }
                      },
                      min: 0,
                      max: 100
                    }
                  }
                }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Security Alert Popup */}
      <SecurityAlert
        isVisible={securityAlert.isVisible}
        onClose={() => setSecurityAlert({ isVisible: false, url: '', riskScore: 0, prediction: '' })}
        url={securityAlert.url}
        riskScore={securityAlert.riskScore}
        prediction={securityAlert.prediction}
      />
    </div>
  );
}

export default Dashboard;

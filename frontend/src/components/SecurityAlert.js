import React, { useEffect } from 'react';

function SecurityAlert({ isVisible, onClose, url, riskScore, prediction }) {
  useEffect(() => {
    if (isVisible) {
      // Auto-close after 10 seconds
      const timer = setTimeout(() => {
        onClose();
      }, 10000);

      return () => clearTimeout(timer);
    }
  }, [isVisible, onClose]);

  if (!isVisible) return null;

  const isHighRisk = riskScore > 50 || prediction === 'Malware Site';

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.8)',
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      zIndex: 9999,
      animation: 'fadeIn 0.3s ease-in'
    }}>
      <div style={{
        background: 'linear-gradient(135deg, #ff0000, #cc0000)',
        border: '4px solid #ff4444',
        borderRadius: '15px',
        padding: '30px',
        maxWidth: '500px',
        width: '90%',
        textAlign: 'center',
        boxShadow: '0 0 30px rgba(255, 0, 0, 0.8)',
        animation: 'pulse 1s infinite'
      }}>
        <div style={{
          fontSize: '48px',
          marginBottom: '20px',
          animation: 'bounce 1s infinite'
        }}>
          🚨
        </div>

        <h2 style={{
          color: '#ffffff',
          fontSize: '28px',
          marginBottom: '15px',
          textShadow: '2px 2px 4px rgba(0,0,0,0.8)',
          fontWeight: 'bold'
        }}>
          SECURITY ALERT: DANGEROUS WEBSITE BLOCKED
        </h2>

        <div style={{
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          border: '2px solid #ffffff',
          borderRadius: '10px',
          padding: '20px',
          marginBottom: '20px'
        }}>
          <p style={{
            color: '#ffffff',
            fontSize: '16px',
            lineHeight: '1.6',
            margin: '0',
            fontWeight: 'bold'
          }}>
            This website has been identified as <span style={{ color: '#ffff00', fontSize: '18px' }}>HIGH RISK</span> and has been blocked to protect your device and data.
          </p>
        </div>

        <div style={{
          backgroundColor: 'rgba(0, 0, 0, 0.7)',
          borderRadius: '8px',
          padding: '15px',
          marginBottom: '20px'
        }}>
          <div style={{ color: '#ffcccc', fontSize: '14px', marginBottom: '5px' }}>
            <strong>URL:</strong> {url}
          </div>
          <div style={{ color: '#ffcccc', fontSize: '14px', marginBottom: '5px' }}>
            <strong>Risk Score:</strong> <span style={{ color: '#ffff00', fontWeight: 'bold' }}>{riskScore}/100</span>
          </div>
          <div style={{ color: '#ffcccc', fontSize: '14px' }}>
            <strong>Classification:</strong> <span style={{ color: '#ff6666', fontWeight: 'bold' }}>{prediction}</span>
          </div>
        </div>

        <div style={{
          display: 'flex',
          gap: '15px',
          justifyContent: 'center',
          flexWrap: 'wrap'
        }}>
          <button
            onClick={onClose}
            style={{
              backgroundColor: '#ffffff',
              color: '#ff0000',
              border: '2px solid #ffffff',
              borderRadius: '8px',
              padding: '12px 24px',
              fontSize: '16px',
              fontWeight: 'bold',
              cursor: 'pointer',
              transition: 'all 0.3s ease',
              minWidth: '120px'
            }}
            onMouseOver={(e) => {
              e.target.style.backgroundColor = '#ff0000';
              e.target.style.color = '#ffffff';
            }}
            onMouseOut={(e) => {
              e.target.style.backgroundColor = '#ffffff';
              e.target.style.color = '#ff0000';
            }}
          >
            Dismiss Alert
          </button>

          <button
            onClick={() => {
              // Could add more actions here like reporting the URL
              onClose();
            }}
            style={{
              backgroundColor: '#ff4444',
              color: '#ffffff',
              border: '2px solid #ff6666',
              borderRadius: '8px',
              padding: '12px 24px',
              fontSize: '16px',
              fontWeight: 'bold',
              cursor: 'pointer',
              transition: 'all 0.3s ease',
              minWidth: '120px'
            }}
            onMouseOver={(e) => {
              e.target.style.backgroundColor = '#cc0000';
            }}
            onMouseOut={(e) => {
              e.target.style.backgroundColor = '#ff4444';
            }}
          >
            Report URL
          </button>
        </div>

        <div style={{
          marginTop: '15px',
          fontSize: '12px',
          color: '#ffcccc',
          opacity: 0.8
        }}>
          This alert will auto-close in 10 seconds
        </div>
      </div>
    </div>
  );
}

export default SecurityAlert;

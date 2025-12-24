import React, { useState, useEffect } from 'react';
import { Pie, Line, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
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
  BarElement,
  Title
);

function ThreatLogs({ logs }) {
  const [analytics, setAnalytics] = useState({
    totalScans: 0,
    safeUrls: 0,
    maliciousUrls: 0,
    riskDistribution: { low: 0, medium: 0, high: 0 },
    topCountries: {},
    recentActivity: []
  });

  useEffect(() => {
    if (logs.length > 0) {
      const newAnalytics = {
        totalScans: logs.length,
        safeUrls: logs.filter(log => log.prediction === 'Benign').length,
        maliciousUrls: logs.filter(log => log.prediction === 'Malware Site').length,
        riskDistribution: { low: 0, medium: 0, high: 0 },
        topCountries: {},
        recentActivity: logs.slice(-10).reverse()
      };

      // Calculate risk distribution
      logs.forEach(log => {
        const riskScore = log.riskScore || 0;
        if (riskScore < 33) newAnalytics.riskDistribution.low++;
        else if (riskScore < 66) newAnalytics.riskDistribution.medium++;
        else newAnalytics.riskDistribution.high++;
      });

      // Calculate top countries
      logs.forEach(log => {
        const country = log.country || 'Unknown';
        newAnalytics.topCountries[country] = (newAnalytics.topCountries[country] || 0) + 1;
      });

      setAnalytics(newAnalytics);
    }
  }, [logs]);

  const getRiskColor = (risk) => {
    switch (risk) {
      case 'low': return '#00ff00';
      case 'medium': return '#ffff00';
      case 'high': return '#ff0000';
      default: return '#666666';
    }
  };

  const getPredictionColor = (prediction) => {
    return prediction === 'Benign' ? '#00ff00' : '#ff0000';
  };

  return (
    <div className="analytics-dashboard">
      <h2 style={{ color: '#00ff00', marginBottom: '20px', textAlign: 'center' }}>
        Threat Intelligence Analytics
      </h2>

      {/* Summary Cards */}
      <div className="analytics-grid">
        <div className="metric-card">
          <h3>Total Scans</h3>
          <div className="metric-value" style={{ color: '#00ffff' }}>{analytics.totalScans}</div>
        </div>
        <div className="metric-card">
          <h3>Safe URLs</h3>
          <div className="metric-value" style={{ color: '#00ff00' }}>{analytics.safeUrls}</div>
        </div>
        <div className="metric-card">
          <h3>Malicious URLs</h3>
          <div className="metric-value" style={{ color: '#ff0000' }}>{analytics.maliciousUrls}</div>
        </div>
        <div className="metric-card">
          <h3>Threat Ratio</h3>
          <div className="metric-value" style={{ color: '#ffff00' }}>
            {analytics.totalScans > 0 ? ((analytics.maliciousUrls / analytics.totalScans) * 100).toFixed(1) : 0}%
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px', marginBottom: '30px' }}>
        {/* Pie Chart for Safe vs Malicious */}
        <div className="chart-container">
          <h4>URL Safety Distribution</h4>
          <Pie
            data={{
              labels: ['Safe URLs', 'Malicious URLs'],
              datasets: [{
                data: [analytics.safeUrls, analytics.maliciousUrls],
                backgroundColor: [
                  '#00ff00',
                  '#ff0000'
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

        {/* Line Chart for Risk Scores Over Time */}
        <div className="chart-container">
          <h4>Risk Score Trends</h4>
          <Line
            data={{
              labels: analytics.recentActivity.map((_, index) => `Scan ${index + 1}`),
              datasets: [{
                label: 'Risk Score',
                data: analytics.recentActivity.map(log => log.riskScore),
                borderColor: '#00ff00',
                backgroundColor: 'rgba(0, 255, 0, 0.1)',
                borderWidth: 3,
                pointBackgroundColor: '#00ff00',
                pointBorderColor: '#00ff00',
                pointRadius: 6,
                pointHoverRadius: 10,
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

      {/* Risk Distribution Chart */}
      <div className="chart-container">
        <h3>Risk Distribution</h3>
        <div className="bar-chart">
          <div className="bar-item">
            <span className="bar-label">Low Risk</span>
            <div className="bar">
              <div
                className="bar-fill"
                style={{
                  width: `${analytics.totalScans > 0 ? (analytics.riskDistribution.low / analytics.totalScans) * 100 : 0}%`,
                  backgroundColor: getRiskColor('low')
                }}
              ></div>
            </div>
            <span className="bar-value">{analytics.riskDistribution.low}</span>
          </div>
          <div className="bar-item">
            <span className="bar-label">Medium Risk</span>
            <div className="bar">
              <div
                className="bar-fill"
                style={{
                  width: `${analytics.totalScans > 0 ? (analytics.riskDistribution.medium / analytics.totalScans) * 100 : 0}%`,
                  backgroundColor: getRiskColor('medium')
                }}
              ></div>
            </div>
            <span className="bar-value">{analytics.riskDistribution.medium}</span>
          </div>
          <div className="bar-item">
            <span className="bar-label">High Risk</span>
            <div className="bar">
              <div
                className="bar-fill"
                style={{
                  width: `${analytics.totalScans > 0 ? (analytics.riskDistribution.high / analytics.totalScans) * 100 : 0}%`,
                  backgroundColor: getRiskColor('high')
                }}
              ></div>
            </div>
            <span className="bar-value">{analytics.riskDistribution.high}</span>
          </div>
        </div>
      </div>

      {/* Top Countries Bar Chart */}
      <div className="chart-container">
        <h4>Top Threat Countries</h4>
        <Bar
          data={{
            labels: Object.entries(analytics.topCountries)
              .sort(([,a], [,b]) => b - a)
              .slice(0, 5)
              .map(([country]) => country),
            datasets: [{
              label: 'Number of Threats',
              data: Object.entries(analytics.topCountries)
                .sort(([,a], [,b]) => b - a)
                .slice(0, 5)
                .map(([, count]) => count),
              backgroundColor: '#00ffff',
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
                  color: '#00ff00'
                }
              }
            }
          }}
        />
      </div>

      {/* Recent Activity */}
      <div className="chart-container">
        <h3>Recent Activity</h3>
        <div className="activity-list">
          {analytics.recentActivity.map((log, index) => (
            <div key={index} className="activity-item">
              <div className="activity-url" style={{ color: '#00ffff' }}>
                {log.url.length > 50 ? log.url.substring(0, 50) + '...' : log.url}
              </div>
              <div className="activity-details">
                <span style={{ color: getPredictionColor(log.prediction) }}>
                  {log.prediction}
                </span>
                <span>Risk: {log.riskScore}/100</span>
                <span>{log.country}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default ThreatLogs;

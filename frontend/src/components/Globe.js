import React, { useRef, useEffect, useState } from 'react';
import * as THREE from 'three';

// Country coordinates and continent mapping
const countries = {
  // North America
  'United States': { coords: [[-124.7, 48.4], [-124.7, 49.4], [-95.2, 49.4], [-95.2, 49.4], [-87.6, 49.4], [-82.7, 49.4], [-74.7, 45.0], [-67.0, 45.0], [-67.0, 47.5], [-124.7, 48.4]], continent: 'North America' },
  'Canada': { coords: [[-141.0, 60.0], [-141.0, 83.1], [-52.6, 83.1], [-52.6, 60.0], [-141.0, 60.0]], continent: 'North America' },
  'Mexico': { coords: [[-118.4, 32.5], [-118.4, 14.5], [-86.8, 14.5], [-86.8, 32.5], [-118.4, 32.5]], continent: 'North America' },

  // South America
  'Brazil': { coords: [[-73.0, 5.3], [-73.0, -33.7], [-35.0, -33.7], [-35.0, 5.3], [-73.0, 5.3]], continent: 'South America' },
  'Argentina': { coords: [[-73.6, -21.8], [-73.6, -55.1], [-53.6, -55.1], [-53.6, -21.8], [-73.6, -21.8]], continent: 'South America' },
  'Colombia': { coords: [[-79.0, 12.6], [-79.0, -4.2], [-66.9, -4.2], [-66.9, 12.6], [-79.0, 12.6]], continent: 'South America' },

  // Europe
  'United Kingdom': { coords: [[-5.7, 58.6], [-5.7, 50.7], [1.8, 50.7], [1.8, 58.6], [-5.7, 58.6]], continent: 'Europe' },
  'Germany': { coords: [[5.9, 54.9], [5.9, 47.3], [15.0, 47.3], [15.0, 54.9], [5.9, 54.9]], continent: 'Europe' },
  'France': { coords: [[-5.1, 51.1], [-5.1, 42.3], [8.2, 42.3], [8.2, 51.1], [-5.1, 51.1]], continent: 'Europe' },
  'Italy': { coords: [[6.6, 47.1], [6.6, 36.6], [18.5, 36.6], [18.5, 47.1], [6.6, 47.1]], continent: 'Europe' },
  'Spain': { coords: [[-9.3, 43.8], [-9.3, 36.0], [3.3, 36.0], [3.3, 43.8], [-9.3, 43.8]], continent: 'Europe' },

  // Asia
  'Russia': { coords: [[19.6, 82.0], [19.6, 41.2], [180.0, 41.2], [180.0, 82.0], [19.6, 82.0]], continent: 'Asia' },
  'China': { coords: [[73.5, 53.6], [73.5, 18.2], [135.0, 18.2], [135.0, 53.6], [73.5, 53.6]], continent: 'Asia' },
  'India': { coords: [[68.1, 35.5], [68.1, 8.1], [97.4, 8.1], [97.4, 35.5], [68.1, 35.5]], continent: 'Asia' },
  'Japan': { coords: [[128.2, 45.5], [128.2, 30.0], [145.8, 30.0], [145.8, 45.5], [128.2, 45.5]], continent: 'Asia' },

  // Africa
  'Egypt': { coords: [[24.7, 31.6], [24.7, 22.0], [36.9, 22.0], [36.9, 31.6], [24.7, 31.6]], continent: 'Africa' },
  'South Africa': { coords: [[16.5, -22.1], [16.5, -34.8], [32.9, -34.8], [32.9, -22.1], [16.5, -22.1]], continent: 'Africa' },
  'Nigeria': { coords: [[2.7, 13.9], [2.7, 4.3], [14.7, 4.3], [14.7, 13.9], [2.7, 13.9]], continent: 'Africa' },

  // Oceania
  'Australia': { coords: [[113.2, -10.1], [113.2, -43.6], [153.6, -43.6], [153.6, -10.1], [113.2, -10.1]], continent: 'Oceania' }
};

function Globe({ logs = [] }) {
  const mountRef = useRef(null);
  const [hoveredCountry, setHoveredCountry] = useState(null);
  const [threatData, setThreatData] = useState({});

  // Process threat data by country with enhanced aggregation
  useEffect(() => {
    const countryThreats = {};
    logs.forEach(log => {
      const country = log.country || 'Unknown';
      if (!countryThreats[country]) {
        countryThreats[country] = {
          count: 0,
          risk: 0,
          malicious: 0,
          totalRisk: 0,
          safe: 0,
          highRisk: 0,
          recentScans: []
        };
      }
      countryThreats[country].count += 1;
      countryThreats[country].totalRisk += log.riskScore || 0;
      if (log.prediction === 'Malware Site') {
        countryThreats[country].malicious += 1;
      } else {
        countryThreats[country].safe += 1;
      }
      if ((log.riskScore || 0) > 70) {
        countryThreats[country].highRisk += 1;
      }

      // Keep track of recent scans (last 5 per country)
      countryThreats[country].recentScans.unshift(log);
      countryThreats[country].recentScans = countryThreats[country].recentScans.slice(0, 5);
    });

    // Calculate average risk for each country
    Object.keys(countryThreats).forEach(country => {
      countryThreats[country].risk = countryThreats[country].totalRisk / countryThreats[country].count;
    });

    setThreatData(countryThreats);
  }, [logs]);

  useEffect(() => {
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });

    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setClearColor(0x000000, 0);
    mountRef.current.appendChild(renderer.domElement);

    // Create textured Earth globe
    const geometry = new THREE.SphereGeometry(5, 64, 64);
    let globe;

    const textureLoader = new THREE.TextureLoader();
    textureLoader.load(
      'https://upload.wikimedia.org/wikipedia/commons/8/83/Equirectangular_projection_SW.jpg',
      (texture) => {
        const material = new THREE.MeshPhongMaterial({
          map: texture,
          transparent: false,
        });
        globe = new THREE.Mesh(geometry, material);
        scene.add(globe);
        animate();
      },
      undefined,
      (error) => {
        console.error('Error loading Earth texture:', error);
        // Fallback to basic material showing land
        const material = new THREE.MeshPhongMaterial({
          color: 0x228B22,
        });
        globe = new THREE.Mesh(geometry, material);
        scene.add(globe);
        animate();
      }
    );

    // Add ambient light for better texture visibility
    const ambientLight = new THREE.AmbientLight(0x404040, 0.6);
    scene.add(ambientLight);

    // Add directional light to simulate sun
    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8);
    directionalLight.position.set(5, 3, 5);
    scene.add(directionalLight);

    // Add country borders and threat visualization
    const addCountryShapes = () => {
      Object.entries(countries).forEach(([countryName, countryData]) => {
        const coords = countryData.coords;
        const threatLevel = threatData[countryName];
        const hasThreats = threatLevel && threatLevel.count > 0;

        // Create country boundary lines for educational display
        const points = [];
        coords.forEach((coord) => {
          const [lon, lat] = coord;
          const phi = (90 - lat) * (Math.PI / 180);
          const theta = (lon + 180) * (Math.PI / 180);

          const x = -(Math.sin(phi) * Math.cos(theta)) * 5.01;
          const y = Math.cos(phi) * 5.01;
          const z = Math.sin(phi) * Math.sin(theta) * 5.01;

          points.push(new THREE.Vector3(x, y, z));
        });

        // Close the loop by connecting back to first point
        if (points.length > 0) {
          points.push(points[0].clone());
        }

        // Add threat indicators (spikes/pins) for countries with threats
        if (hasThreats) {
          const centerLat = coords.reduce((sum, coord) => sum + coord[1], 0) / coords.length;
          const centerLon = coords.reduce((sum, coord) => sum + coord[0], 0) / coords.length;

          const phi = (90 - centerLat) * (Math.PI / 180);
          const theta = (centerLon + 180) * (Math.PI / 180);

          const x = -(Math.sin(phi) * Math.cos(theta)) * 5.2;
          const z = Math.sin(phi) * Math.sin(theta) * 5.2;
          const y = Math.cos(phi) * 5.2;

          // Create threat spike (column)
          const spikeGeometry = new THREE.ConeGeometry(0.05, 0.3 + (threatLevel.count * 0.05), 8);
          const spikeMaterial = new THREE.MeshBasicMaterial({
            color: 0xff0000 // Red for threats
          });
          const spike = new THREE.Mesh(spikeGeometry, spikeMaterial);
          spike.position.set(x, y, z);
          spike.lookAt(0, 0, 0);
          scene.add(spike);

          // Add pulsing effect for high threat countries
          if (threatLevel.risk > 70) {
            const glowGeometry = new THREE.SphereGeometry(0.1, 8, 8);
            const glowMaterial = new THREE.MeshBasicMaterial({
              color: 0xff0000,
              transparent: true,
              opacity: 0.5
            });
            const glow = new THREE.Mesh(glowGeometry, glowMaterial);
            glow.position.set(x, y, z);
            scene.add(glow);

            // Animate glow
            const animateGlow = () => {
              glow.scale.setScalar(1 + Math.sin(Date.now() * 0.005) * 0.3);
              glow.material.opacity = 0.3 + Math.sin(Date.now() * 0.01) * 0.2;
              requestAnimationFrame(animateGlow);
            };
            animateGlow();
          }
        }
      });
    };

    addCountryShapes();

    camera.position.z = 12;

    const animate = () => {
      requestAnimationFrame(animate);
      if (globe) {
        globe.rotation.y += 0.005;
      }
      renderer.render(scene, camera);
    };

    // Cleanup function to dispose of Three.js resources
    return () => {
      if (mountRef.current && renderer.domElement && mountRef.current.contains(renderer.domElement)) {
        try {
          mountRef.current.removeChild(renderer.domElement);
        } catch (error) {
          console.warn('Failed to remove renderer element:', error);
        }
      }
      renderer.dispose();
      scene.clear();
    };

  }, []);

  // Group countries by continent
  const countriesByContinent = Object.entries(countries).reduce((acc, [countryName, data]) => {
    const continent = data.continent;
    if (!acc[continent]) acc[continent] = [];
    acc[continent].push(countryName);
    return acc;
  }, {});

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div ref={mountRef} style={{ width: '100%', height: '70%' }}>
        {hoveredCountry && (
          <div style={{
            position: 'absolute',
            top: 10,
            left: 10,
            background: 'rgba(0, 0, 0, 0.8)',
            color: 'white',
            padding: '10px',
            borderRadius: '5px',
            fontSize: '14px',
            zIndex: 1000
          }}>
            <h3>{hoveredCountry.country}</h3>
            {hoveredCountry.threatLevel && (
              <div>
                <p>Threats: {hoveredCountry.threatLevel.count}</p>
                <p>Risk Level: {hoveredCountry.threatLevel.risk.toFixed(2)}</p>
                <p>Malicious: {hoveredCountry.threatLevel.malicious}</p>
                <p>Safe: {hoveredCountry.threatLevel.safe}</p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Country and Continent List Below Globe */}
      <div style={{
        height: '30%',
        overflowY: 'auto',
        background: 'rgba(0, 0, 0, 0.8)',
        color: '#00ff00',
        padding: '10px',
        borderTop: '2px solid #00ff00'
      }}>
        <h3 style={{ color: '#00ff00', marginBottom: '10px', textAlign: 'center' }}>
          Global Threat Map - Countries & Continents
        </h3>
        {Object.entries(countriesByContinent).map(([continent, countryList]) => (
          <div key={continent} style={{ marginBottom: '15px' }}>
            <h4 style={{
              color: '#ffff00',
              marginBottom: '5px',
              borderBottom: '1px solid #ffff00',
              paddingBottom: '3px'
            }}>
              {continent}
            </h4>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
              gap: '5px'
            }}>
              {countryList.map(countryName => {
                const threatLevel = threatData[countryName];
                const hasThreats = threatLevel && threatLevel.count > 0;
                return (
                  <div
                    key={countryName}
                    style={{
                      padding: '3px 6px',
                      background: hasThreats ? 'rgba(255, 0, 0, 0.3)' : 'rgba(0, 255, 0, 0.1)',
                      border: `1px solid ${hasThreats ? '#ff0000' : '#00ff00'}`,
                      borderRadius: '3px',
                      fontSize: '12px',
                      color: hasThreats ? '#ffcccc' : '#00ff00',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center'
                    }}
                  >
                    <span>{countryName}</span>
                    {hasThreats && (
                      <span style={{
                        background: '#ff0000',
                        color: 'white',
                        padding: '1px 3px',
                        borderRadius: '2px',
                        fontSize: '10px',
                        fontWeight: 'bold'
                      }}>
                        {threatLevel.count}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Globe;

 
import React from 'react';
import { createRoot } from 'react-dom/client';
import { ArtifactIntelligencePlatform } from './components.jsx';

// Global CSS variables for the professional theme
const style = document.createElement('style');
style.textContent = `
  :root {
    --bg-base: #0B0E14;
    --bg-surface: #151922;
    --bg-surface-2: #1C2230;
    --bg-surface-3: #232834;
    --accent-primary: #4A63E7;
    --accent-primary-hover: #5B72F0;
    --accent-primary-light: rgba(74, 99, 231, 0.1);
    --text-primary: #E8EBF0;
    --text-secondary: #A8B2C3;
    --text-muted: #6B7789;
    --border-default: #2A3142;
    --border-light: rgba(255, 255, 255, 0.06);

    /* Risk Severity Colors */
    --risk-critical: #E54D4D;
    --risk-high: #E67E22;
    --risk-medium: #F39C12;
    --risk-low: #3498DB;
    --risk-minimal: #52C41A;

    /* Status Indicators */
    --status-active: #52C41A;
    --status-warning: #FAAD14;
    --status-error: #F5222D;
  }

  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Inter', sans-serif;
    background: var(--bg-base);
    color: var(--text-primary);
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }
`;
document.head.appendChild(style);

function App() {
  return <ArtifactIntelligencePlatform />;
}

createRoot(document.getElementById('root')).render(<App />);
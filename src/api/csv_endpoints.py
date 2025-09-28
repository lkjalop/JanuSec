"""CSV Upload Endpoints for Batch Analysis"""

from fastapi import APIRouter, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
import json
from typing import List
from .csv_handler import get_csv_processor

router = APIRouter(prefix="/api/v1/csv", tags=["CSV Analysis"])

@router.post("/upload")
async def upload_csv(file: UploadFile = File(...)):
    """Upload CSV file for batch artifact analysis"""

    # Validate file type
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")

    # Read file content
    content = await file.read()

    # Process CSV
    processor = get_csv_processor()
    results = await processor.process_csv(content, file.filename)

    if results['status'] == 'error':
        raise HTTPException(status_code=400, detail=results['error'])

    return JSONResponse(content=results)

@router.get("/upload-page")
async def csv_upload_page():
    """Simple HTML page for CSV upload"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>JanuSec CSV Analysis</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background: #f5f5f5;
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 30px;
            }
            .upload-section {
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }
            .file-input {
                padding: 10px;
                margin: 10px 0;
                width: 100%;
                border: 2px dashed #ccc;
                border-radius: 4px;
                cursor: pointer;
            }
            .analyze-btn {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 12px 30px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
                margin-top: 10px;
            }
            .analyze-btn:hover {
                opacity: 0.9;
            }
            .results-section {
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                display: none;
            }
            .result-item {
                padding: 15px;
                margin: 10px 0;
                border-radius: 4px;
                border-left: 4px solid;
            }
            .verdict-malicious {
                border-color: #ff4444;
                background: #ffebeb;
            }
            .verdict-suspicious {
                border-color: #ff8800;
                background: #fff4e6;
            }
            .verdict-pua {
                border-color: #ffbb33;
                background: #fffaed;
            }
            .verdict-controlled {
                border-color: #0099cc;
                background: #e6f7ff;
            }
            .verdict-good {
                border-color: #00c851;
                background: #eafaf1;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .stat-card {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 4px;
                text-align: center;
            }
            .stat-value {
                font-size: 32px;
                font-weight: bold;
                color: #667eea;
            }
            .stat-label {
                color: #666;
                margin-top: 5px;
            }
            .loading {
                display: none;
                text-align: center;
                padding: 20px;
            }
            .spinner {
                border: 4px solid #f3f3f3;
                border-top: 4px solid #667eea;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 0 auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ JanuSec Artifact Analysis</h1>
            <p>Upload CSV files containing process lists for automated security assessment</p>
        </div>

        <div class="upload-section">
            <h2>📤 Upload CSV File</h2>
            <p>CSV should contain columns like: process_name, file_path, hash, command_line, user, host</p>
            <input type="file" id="csvFile" accept=".csv" class="file-input">
            <br>
            <button onclick="analyzeCSV()" class="analyze-btn">🔍 Analyze Artifacts</button>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Analyzing artifacts...</p>
            </div>
        </div>

        <div class="results-section" id="results">
            <h2>📊 Analysis Results</h2>

            <div class="stats-grid" id="stats"></div>

            <h3>Detailed Findings</h3>
            <div id="resultsList"></div>
        </div>

        <script>
            async function analyzeCSV() {
                const fileInput = document.getElementById('csvFile');
                const file = fileInput.files[0];

                if (!file) {
                    alert('Please select a CSV file');
                    return;
                }

                // Show loading
                document.getElementById('loading').style.display = 'block';
                document.getElementById('results').style.display = 'none';

                // Create form data
                const formData = new FormData();
                formData.append('file', file);

                try {
                    const response = await fetch('/api/v1/csv/upload', {
                        method: 'POST',
                        body: formData
                    });

                    const data = await response.json();
                    displayResults(data);
                } catch (error) {
                    alert('Error analyzing file: ' + error.message);
                } finally {
                    document.getElementById('loading').style.display = 'none';
                }
            }

            function displayResults(data) {
                if (data.status === 'error') {
                    alert('Error: ' + data.error);
                    return;
                }

                // Calculate statistics
                const stats = {
                    total: data.results.length,
                    malicious: 0,
                    suspicious: 0,
                    pua: 0,
                    controlled: 0,
                    good: 0
                };

                data.results.forEach(r => {
                    switch(r.verdict) {
                        case 'MALICIOUS': stats.malicious++; break;
                        case 'SUSPICIOUS': stats.suspicious++; break;
                        case 'PUA': stats.pua++; break;
                        case 'CONTROLLED_ITEM': stats.controlled++; break;
                        case 'GOOD': stats.good++; break;
                    }
                });

                // Display statistics
                const statsHtml = `
                    <div class="stat-card">
                        <div class="stat-value">${stats.total}</div>
                        <div class="stat-label">Total Analyzed</div>
                    </div>
                    <div class="stat-card" style="background: #ffebeb;">
                        <div class="stat-value" style="color: #ff4444;">${stats.malicious}</div>
                        <div class="stat-label">Malicious</div>
                    </div>
                    <div class="stat-card" style="background: #fff4e6;">
                        <div class="stat-value" style="color: #ff8800;">${stats.suspicious}</div>
                        <div class="stat-label">Suspicious</div>
                    </div>
                    <div class="stat-card" style="background: #eafaf1;">
                        <div class="stat-value" style="color: #00c851;">${stats.good}</div>
                        <div class="stat-label">Good</div>
                    </div>
                `;
                document.getElementById('stats').innerHTML = statsHtml;

                // Display detailed results
                let resultsHtml = '';
                data.results.forEach((result, index) => {
                    const verdictClass = 'verdict-' + result.verdict.toLowerCase().replace('_', '-');
                    resultsHtml += `
                        <div class="result-item ${verdictClass}">
                            <strong>#${index + 1} - ${result.process_name || 'Unknown Process'}</strong>
                            <br>
                            <strong>Verdict:</strong> ${result.verdict} (Risk: ${(result.risk_score * 100).toFixed(0)}%)
                            <br>
                            <strong>File Path:</strong> ${result.file_path || 'N/A'}
                            <br>
                            <strong>Hash:</strong> ${result.hash || 'N/A'}
                            <br>
                            <strong>Factors:</strong> ${result.factors.join(', ') || 'None'}
                            <br>
                            <strong>Recommendations:</strong>
                            <ul>
                                ${result.recommendations.map(r => '<li>' + r + '</li>').join('')}
                            </ul>
                        </div>
                    `;
                });

                document.getElementById('resultsList').innerHTML = resultsHtml;
                document.getElementById('results').style.display = 'block';
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
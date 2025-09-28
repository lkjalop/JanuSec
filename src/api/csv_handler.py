"""CSV Batch Ingestion Handler for Artifact Analysis"""

import csv
import hashlib
import io
import json
import uuid
from datetime import datetime
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class CSVProcessor:
    """Process CSV files containing process/artifact lists"""

    def __init__(self):
        self.supported_columns = [
            'process_name', 'file_path', 'hash', 'pid',
            'parent_process', 'command_line', 'user', 'host'
        ]

    async def process_csv(self, file_content: bytes, filename: str = "upload.csv") -> Dict[str, Any]:
        """Process uploaded CSV file and return analysis results"""
        try:
            # Parse CSV
            text_content = file_content.decode('utf-8-sig')  # Handle BOM
            csv_reader = csv.DictReader(io.StringIO(text_content))

            artifacts = []
            for row_num, row in enumerate(csv_reader, 1):
                artifact = self._parse_row(row, row_num)
                if artifact:
                    artifacts.append(artifact)

            # Batch analysis
            results = await self._analyze_batch(artifacts)

            return {
                'status': 'success',
                'filename': filename,
                'total_rows': len(artifacts),
                'processed': len(results),
                'timestamp': datetime.utcnow().isoformat(),
                'results': results
            }

        except Exception as e:
            logger.error(f"CSV processing error: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'filename': filename
            }

    def _parse_row(self, row: Dict, row_num: int) -> Dict[str, Any]:
        """Parse single CSV row into artifact format"""
        artifact = {
            'id': f"csv_row_{row_num}_{uuid.uuid4().hex[:8]}",
            'source': 'csv_upload',
            'row_number': row_num,
            'timestamp': datetime.utcnow().isoformat()
        }

        # Map CSV columns to artifact fields
        for col, value in row.items():
            if not value:  # Skip empty values
                continue

            col_lower = col.lower().strip()

            if 'process' in col_lower or 'name' in col_lower:
                artifact['process_name'] = value.strip()
            elif 'path' in col_lower or 'file' in col_lower:
                artifact['file_path'] = value.strip()
            elif 'hash' in col_lower or 'md5' in col_lower or 'sha' in col_lower:
                artifact['hash'] = value.strip().lower()
            elif 'pid' in col_lower:
                artifact['pid'] = value.strip()
            elif 'parent' in col_lower:
                artifact['parent_process'] = value.strip()
            elif 'command' in col_lower or 'cmd' in col_lower:
                artifact['command_line'] = value.strip()
            elif 'user' in col_lower:
                artifact['user'] = value.strip()
            elif 'host' in col_lower or 'computer' in col_lower:
                artifact['host'] = value.strip()
            else:
                # Store unknown columns as metadata
                artifact[f'meta_{col_lower}'] = value.strip()

        return artifact if len(artifact) > 4 else None  # Need at least some data

    async def _analyze_batch(self, artifacts: List[Dict]) -> List[Dict]:
        """Analyze batch of artifacts and return verdicts"""
        results = []

        for artifact in artifacts:
            # Simple risk assessment (would integrate with main pipeline)
            risk_score = self._calculate_risk(artifact)
            verdict = self._classify_verdict(risk_score)

            results.append({
                'artifact_id': artifact['id'],
                'process_name': artifact.get('process_name', 'unknown'),
                'file_path': artifact.get('file_path', ''),
                'hash': artifact.get('hash', ''),
                'verdict': verdict,
                'risk_score': risk_score,
                'confidence': 0.7,  # Placeholder
                'factors': self._extract_factors(artifact),
                'recommendations': self._get_recommendations(verdict, artifact)
            })

        return results

    def _calculate_risk(self, artifact: Dict) -> float:
        """Calculate risk score for artifact"""
        risk = 0.0

        # Check suspicious patterns
        process_name = artifact.get('process_name', '').lower()
        command_line = artifact.get('command_line', '').lower()
        file_path = artifact.get('file_path', '').lower()

        # Known suspicious processes
        suspicious_processes = [
            'powershell', 'cmd', 'wscript', 'cscript', 'rundll32',
            'regsvr32', 'mshta', 'bitsadmin', 'certutil'
        ]

        for proc in suspicious_processes:
            if proc in process_name:
                risk += 0.3

        # Encoded commands
        if 'powershell' in process_name and '-e' in command_line:
            risk += 0.5

        # Suspicious paths
        suspicious_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\', '%temp%']
        for path in suspicious_paths:
            if path in file_path.lower():
                risk += 0.2

        # Unknown hash (would check VirusTotal in production)
        if artifact.get('hash') and len(artifact['hash']) == 32:
            # Simulate hash check
            if artifact['hash'].startswith('0000'):  # Obviously fake
                risk += 0.1

        return min(risk, 1.0)  # Cap at 1.0

    def _classify_verdict(self, risk_score: float) -> str:
        """Classify verdict based on risk score"""
        if risk_score >= 0.8:
            return "MALICIOUS"
        elif risk_score >= 0.6:
            return "SUSPICIOUS"
        elif risk_score >= 0.4:
            return "PUA"
        elif risk_score >= 0.2:
            return "CONTROLLED_ITEM"
        else:
            return "GOOD"

    def _extract_factors(self, artifact: Dict) -> List[str]:
        """Extract detection factors from artifact"""
        factors = []

        process_name = artifact.get('process_name', '').lower()
        command_line = artifact.get('command_line', '').lower()

        if 'powershell' in process_name:
            factors.append('powershell_execution')
        if '-e' in command_line and 'powershell' in process_name:
            factors.append('encoded_command')
        if '\\temp\\' in artifact.get('file_path', '').lower():
            factors.append('temp_directory_execution')
        if artifact.get('parent_process', '').lower() in ['winword.exe', 'excel.exe']:
            factors.append('office_child_process')

        return factors

    def _get_recommendations(self, verdict: str, artifact: Dict) -> List[str]:
        """Get recommendations based on verdict"""
        recommendations = []

        if verdict == "MALICIOUS":
            recommendations.extend([
                "Isolate affected endpoint immediately",
                "Terminate process if still running",
                "Collect forensic artifacts",
                "Check for persistence mechanisms"
            ])
        elif verdict == "SUSPICIOUS":
            recommendations.extend([
                "Monitor process behavior",
                "Check network connections",
                "Review parent process chain",
                "Submit hash to VirusTotal"
            ])
        elif verdict == "PUA":
            recommendations.extend([
                "Review software policy compliance",
                "Check if authorized by IT",
                "Consider removal if unauthorized"
            ])
        elif verdict == "CONTROLLED_ITEM":
            recommendations.extend([
                "Verify user authorization",
                "Apply access restrictions if needed",
                "Add to monitoring watchlist"
            ])
        else:
            recommendations.append("No action required - legitimate software")

        return recommendations

# Singleton instance
_csv_processor = None

def get_csv_processor() -> CSVProcessor:
    global _csv_processor
    if _csv_processor is None:
        _csv_processor = CSVProcessor()
    return _csv_processor
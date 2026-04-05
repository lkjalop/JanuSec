from typing import List, Dict
from datetime import datetime, timedelta
import logging, os, json

logger = logging.getLogger(__name__)

TENANT_DIR = os.getenv('TENANT_DATA_DIR','data/tenants')


def _tenant_connectors_path(tenant_id: str) -> str:
    safe = tenant_id.replace('..','').replace('/','_')
    return os.path.join(TENANT_DIR, safe, 'connectors.json')


class TenantAwareMissingLogDetector:
    def __init__(self, db_connection=None):
        self.db = db_connection
        self._tenant_connectors_cache = {}
        self._cache_ttl = timedelta(minutes=5)
        self._last_cache_update = {}

    def get_tenant_connectors(self, tenant_id: str) -> List[Dict]:
        now = datetime.utcnow()
        if tenant_id in self._tenant_connectors_cache:
            last = self._last_cache_update.get(tenant_id)
            if last and (now - last) < self._cache_ttl:
                return self._tenant_connectors_cache[tenant_id]

        path = _tenant_connectors_path(tenant_id)
        res = []
        try:
            if os.path.exists(path):
                with open(path,'r',encoding='utf-8') as fh:
                    res = json.load(fh)
        except Exception:
            res = []

        self._tenant_connectors_cache[tenant_id] = res
        self._last_cache_update[tenant_id] = now
        return res

    def check_missing_logs(self, tenant_id: str, current_time: datetime) -> List[Dict]:
        connectors = self.get_tenant_connectors(tenant_id)
        missing_logs = []
        for connector in connectors:
            category = connector.get('connector_category')
            conn_type = connector.get('connector_type')
            conn_name = connector.get('connector_name') or conn_type
            threshold_minutes = connector.get('missing_log_threshold_minutes') or connector.get('config',{}).get('threshold') or 30

            # For now, we can't query events DB in this lightweight implementation.
            # We'll mark logs as present (no missing) if connector was recently configured.
            # Later: query events table for last timestamp.
            last_seen = None
            gap_minutes = 0
            if last_seen is None:
                gap_minutes = 0

            # If connector has an explicit disabled flag, skip
            if connector.get('enabled') is False:
                continue

            if gap_minutes > threshold_minutes:
                missing_logs.append({
                    'tenant_id': tenant_id,
                    'connector_category': category,
                    'connector_type': conn_type,
                    'connector_name': conn_name,
                    'last_seen': last_seen,
                    'gap_minutes': int(gap_minutes),
                    'threshold_minutes': threshold_minutes,
                    'severity': 'LOW',
                    'recommended_actions': [f'Check {conn_type} collector']
                })

        return missing_logs

    def analyze_missing_log_root_cause(self, tenant_id: str, connector_type: str) -> Dict:
        # Lightweight placeholder implementation
        return {
            'connector_type': connector_type,
            'possible_causes': ['unknown - requires investigation'],
            'auto_remediation': None,
            'severity': 'MEDIUM'
        }

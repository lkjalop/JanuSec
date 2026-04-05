import os
import json
from typing import Dict, Any, List

DATA_DIR = os.getenv('TENANT_DATA_DIR') or os.path.join('data', 'tenants')


class TenantPlaybookGenerator:
    """Lightweight file-backed playbook generator/persistence for tenants.

    Stores playbooks under: data/tenants/<tenant>/playbooks.json as a list of playbook objects.
    """

    def __init__(self, base_dir: str | None = None):
        self.base_dir = base_dir or DATA_DIR
        os.makedirs(self.base_dir, exist_ok=True)

    def _tenant_path(self, tenant: str) -> str:
        td = os.path.join(self.base_dir, tenant)
        os.makedirs(td, exist_ok=True)
        return os.path.join(td, 'playbooks.json')

    def list_playbooks(self, tenant: str) -> List[Dict[str, Any]]:
        path = self._tenant_path(tenant)
        if not os.path.exists(path):
            return []
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f) or []
        except Exception:
            return []

    def save_playbook(self, tenant: str, playbook: Dict[str, Any]) -> Dict[str, Any]:
        path = self._tenant_path(tenant)
        pb_list = self.list_playbooks(tenant)
        # assign id if missing
        if 'id' not in playbook:
            playbook['id'] = f"pb-{len(pb_list)+1}-{os.urandom(4).hex()}"
        pb_list.append(playbook)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(pb_list, f, indent=2)
        return playbook

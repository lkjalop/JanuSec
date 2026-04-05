import logging
import json
import os
from datetime import datetime

logger = logging.getLogger(__name__)


class FileAlertManager:
    def __init__(self, path: str | None = None):
        self.path = path or os.path.join('data', 'alerts.log')
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    async def send_alert(self, alert: dict) -> None:
        try:
            with open(self.path, 'a', encoding='utf-8') as fh:
                rec = {'ts': datetime.utcnow().isoformat(), 'alert': alert}
                fh.write(json.dumps(rec) + '\n')
        except Exception:
            logger.exception('Failed to write alert to file')


def get_alert_manager() -> FileAlertManager:
    path = os.getenv('LOCAL_ALERT_LOG')
    return FileAlertManager(path)

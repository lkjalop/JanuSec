import os
import json
from typing import Optional

_ENV_PATH = os.getenv('CONNECTOR_CHECKPOINTS_PATH')
# When running in fast test mode prefer an isolated per-process checkpoints file
# to avoid stale state interfering with repeated test runs.
if os.getenv('FAST_TEST_MODE', '').lower() in {'1', 'true', 'yes'} or os.getenv('PYTEST_CURRENT_TEST'):
    if _ENV_PATH:
        DEFAULT_PATH = _ENV_PATH
    else:
        DEFAULT_PATH = f"data/checkpoints-{os.getpid()}.json"
else:
    DEFAULT_PATH = _ENV_PATH or 'data/checkpoints.json'

class CheckpointStore:
    def __init__(self, path: Optional[str] = None):
        self.path = path or DEFAULT_PATH
        d = os.path.dirname(self.path) or '.'
        os.makedirs(d, exist_ok=True)
        # If running in fast test mode and the caller did not explicitly
        # override CONNECTOR_CHECKPOINTS_PATH, start with a fresh empty file
        # to ensure tests run deterministically instead of reading previous
        # persisted checkpoints.
        try:
            # Only auto-reset an existing checkpoint file when running in fast-test
            # mode AND the caller did NOT provide an explicit path and the
            # global env var CONNECTOR_CHECKPOINTS_PATH is not set. This avoids
            # clobbering test-supplied temporary checkpoint paths.
            if (
                (os.getenv('FAST_TEST_MODE', '').lower() in {'1', 'true', 'yes'} or os.getenv('PYTEST_CURRENT_TEST'))
                and not os.getenv('CONNECTOR_CHECKPOINTS_PATH')
                and path is None
            ):
                if os.path.exists(self.path):
                    try:
                        with open(self.path, 'w', encoding='utf-8') as f:
                            json.dump({}, f)
                    except Exception:
                        pass
        except Exception:
            pass

    def load(self, key: str) -> Optional[str]:
        try:
            if not os.path.exists(self.path):
                return None
            with open(self.path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data.get(key)
        except Exception:
            return None

    def save(self, key: str, value: str) -> None:
        try:
            data = {}
            if os.path.exists(self.path):
                with open(self.path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            data[key] = value
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except Exception:
            pass

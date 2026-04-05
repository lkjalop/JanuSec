import yaml
from typing import Dict


def load_rate_limits(path: str) -> Dict[str, int]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        return {}
    except Exception:
        return {}

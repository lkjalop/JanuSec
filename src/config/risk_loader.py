from __future__ import annotations
import json, os, threading, hashlib, time
from typing import Any, Dict, Tuple

_DEFAULT = {
    "version": 1,
    "weights": {
        "lateral": 0.3,
        "priv_escalation": 0.5,
        "cloud_pivot": 0.25,
        "new_host": 0.25,
        "high_value_touch": 0.3,
        "rarity": 0.25,
        "rare_hour": 0.2,
        "isolation_forest_max": 0.4,
        "periodicity": 0.3,
        "ewma_max": 0.25
    },
    "thresholds": {
        "suspicious": 0.5,
        "threat": 1.2,
        "decay_half_life_seconds": 900.0
    },
    "ewma": {"alpha": 0.2, "warmup_min": 10, "residual_scale": 0.4},
    "rarity": {"min_samples": 20, "idf_smoothing": 1.0}
}

_LOCK = threading.RLock()
_CACHE: Dict[str, Any] = {"cfg": _DEFAULT, "hash": "", "path": None, "mtime": 0.0}


def _calc_hash(cfg: Dict[str, Any]) -> str:
    data = json.dumps(cfg, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode()).hexdigest()[:8]


def get_config_path() -> str:
    return os.environ.get("RISK_CONFIG_PATH", os.path.join(os.path.dirname(__file__), "risk_config.json"))


def _validate(cfg: Dict[str, Any]) -> Tuple[bool, str]:
    try:
        for key in ["weights", "thresholds"]:
            if key not in cfg or not isinstance(cfg[key], dict):
                return False, f"missing_section:{key}"
        w = cfg["weights"]
        for wk in ["lateral", "priv_escalation", "cloud_pivot", "new_host", "high_value_touch"]:
            if wk not in w or not isinstance(w[wk], (int, float)) or w[wk] < 0:
                return False, f"bad_weight:{wk}"
        t = cfg["thresholds"]
        for tk in ["suspicious", "threat", "decay_half_life_seconds"]:
            if tk not in t or not isinstance(t[tk], (int, float)) or t[tk] <= 0:
                return False, f"bad_threshold:{tk}"
        return True, "ok"
    except Exception as e:
        return False, f"exception:{e}"


def load_config(force: bool = False) -> Dict[str, Any]:
    path = get_config_path()
    try:
        st = os.stat(path)
        mtime = st.st_mtime
    except FileNotFoundError:
        with _LOCK:
            if not _CACHE.get("hash"):
                _CACHE["hash"] = _calc_hash(_DEFAULT)
            return _CACHE["cfg"]
    with _LOCK:
        if (not force) and _CACHE.get("path") == path and _CACHE.get("mtime") == mtime:
            return _CACHE["cfg"]
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            return _CACHE["cfg"]
        ok, msg = _validate(cfg)
        if not ok:
            return _CACHE["cfg"]
        _CACHE["cfg"] = cfg
        _CACHE["hash"] = _calc_hash(cfg)
        _CACHE["path"] = path
        _CACHE["mtime"] = mtime
        return cfg


def config_hash() -> str:
    with _LOCK:
        if not _CACHE.get("hash"):
            _CACHE["hash"] = _calc_hash(_CACHE["cfg"])  # type: ignore[arg-type]
        return _CACHE["hash"]


def reload_config() -> Dict[str, Any]:
    return load_config(force=True)


def current_config() -> Dict[str, Any]:
    return load_config(force=False)


def half_life_seconds() -> float:
    cfg = current_config()
    return float(cfg.get("thresholds", {}).get("decay_half_life_seconds", 900.0))


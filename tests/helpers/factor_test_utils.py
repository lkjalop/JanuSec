import os
from src.core.quality.factor_quality import get_quality_manager


def reset_quality_manager():
    qm = get_quality_manager()
    qm.tp.clear()
    qm.fp.clear()
    qm.suppressed.clear()
    qm._window.clear()
    qm._window_tp = 0
    qm._window_fp = 0


def enable_feature_flag(flag_name: str):
    # Append flag to FEATURE_FLAGS env var (keeps other flags)
    cur = os.getenv('FEATURE_FLAGS', '')
    parts = [p for p in cur.replace(',', ' ').split() if p]
    if flag_name not in parts:
        parts.append(flag_name)
    os.environ['FEATURE_FLAGS'] = ' '.join(parts)


def use_ci_thresholds():
    # Point the runtime thresholds loader to a deterministic CI file
    curdir = os.path.dirname(os.path.dirname(__file__))
    ci_path = os.path.abspath(os.path.join(curdir, '..', 'data', 'ci_rule_thresholds.json'))
    # If that path doesn't exist under tests, fall back to repository data dir
    if not os.path.exists(ci_path):
        ci_path = os.path.abspath(os.path.join(os.getcwd(), 'data', 'ci_rule_thresholds.json'))
    os.environ['RULE_THRESHOLDS_PATH'] = ci_path

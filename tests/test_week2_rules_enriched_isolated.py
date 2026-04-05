from src.core.correlation.rules.week2.lsass_openprocess_enriched import lsass_openprocess_enriched
from src.core.correlation.rules.week2.registry_run_keys_enriched import registry_run_key_enriched
from src.core.correlation.rules.week2.new_service_nonstandard_path_enriched import new_service_nonstandard_enriched


def test_lsass_openprocess_enriched_positive():
    evt = {
        "target_process": "lsass.exe",
        "caller_process": "powershell.exe",
        "timestamp": 1700000800
    }
    assert lsass_openprocess_enriched(evt)


def test_registry_run_keys_enriched_positive():
    evt = {
        "registry_key": "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "process": "reg.exe",
        "timestamp": 1700000800
    }
    assert registry_run_key_enriched(evt)


def test_new_service_nonstandard_enriched_positive():
    evt = {
        "service_name": "UpdaterSvc",
        "binary_path": "C:\\Users\\bob\\AppData\\Local\\Temp\\updater.exe",
        "timestamp": 1700000900
    }
    assert new_service_nonstandard_enriched(evt)

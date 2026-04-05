from tests.helpers.factor_test_utils import reset_quality_manager, enable_feature_flag


def test_ia_valid_accounts_fires(monkeypatch):
    # enable the rule via feature flags
    monkeypatch.setenv('FEATURE_FLAGS', 'rule_ia_valid_accounts')
    reset_quality_manager()

    from src.core.correlation.rules.weekX.t1078_valid_accounts import ia_valid_accounts

    event = {
        'auth_success_count': 6,
        'src_unusual': True,
    }

    assert ia_valid_accounts(event) is True


def test_ext_remote_services_fires(monkeypatch):
    monkeypatch.setenv('FEATURE_FLAGS', 'rule_ext_remote_services')
    reset_quality_manager()

    from src.core.correlation.rules.weekX.t1133_external_remote import ext_remote_services

    event = {
        'ad_group_change': True,
        'remote_service_access': True,
        'src_external': False,
    }

    assert ext_remote_services(event) is True


def test_correlation_registry_integration(monkeypatch):
    # Ensure rules are enabled and quality manager cleared
    monkeypatch.setenv('FEATURE_FLAGS', 'rule_ia_valid_accounts rule_ext_remote_services')
    reset_quality_manager()

    from src.core.correlation.rules import CORRELATION_RULES

    # Synthetic event likely to trigger at least one rule (auth successes + remote access)
    event = {
        'auth_success_count': 6,
        'src_unusual': True,
        'ad_group_change': True,
        'remote_service_access': True,
        'src_external': True,
    }

    fired = CORRELATION_RULES.evaluate(event)
    assert len(fired) >= 1

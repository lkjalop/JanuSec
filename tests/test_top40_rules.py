import json
from pathlib import Path
from src.core.correlation.rules.registry import CORRELATION_RULES


def load_vector(dir_name, name):
    p = Path(__file__).parent / "data" / dir_name / f"{name}.json"
    return json.loads(p.read_text())


def test_pe_token_theft_combo_pos_neg():
    pos = load_vector('top40', 'pe_token_theft_combo_pos')
    neg = load_vector('top40', 'pe_token_theft_combo_neg')
    assert any(r.id == 'pe_token_theft_combo' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'pe_token_theft_combo' for r in CORRELATION_RULES.evaluate(neg))


def test_pe_uac_bypass_fodhelper_pos_neg():
    pos = load_vector('top40', 'pe_uac_bypass_fodhelper_pos')
    neg = load_vector('top40', 'pe_uac_bypass_fodhelper_neg')
    assert any(r.id == 'pe_uac_bypass_fodhelper' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'pe_uac_bypass_fodhelper' for r in CORRELATION_RULES.evaluate(neg))


def test_pe_namedpipe_impersonation_pos_neg():
    pos = load_vector('top40', 'pe_namedpipe_impersonation_pos')
    neg = load_vector('top40', 'pe_namedpipe_impersonation_neg')
    assert any(r.id == 'pe_namedpipe_impersonation' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'pe_namedpipe_impersonation' for r in CORRELATION_RULES.evaluate(neg))


def test_pe_service_binpath_space_pos_neg():
    pos = load_vector('top40', 'pe_service_binpath_space_pos')
    neg = load_vector('top40', 'pe_service_binpath_space_neg')
    assert any(r.id == 'pe_service_binpath_space' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'pe_service_binpath_space' for r in CORRELATION_RULES.evaluate(neg))


def test_pe_lolbin_msi_pos_neg():
    pos = load_vector('top40', 'pe_lolbin_msi_silent_elevated_pos')
    neg = load_vector('top40', 'pe_lolbin_msi_silent_elevated_neg')
    assert any(r.id == 'pe_lolbin_msi_silent_elevated' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'pe_lolbin_msi_silent_elevated' for r in CORRELATION_RULES.evaluate(neg))


def test_exfil_cloud_storage_new_pos_neg():
    pos = load_vector('top40', 'exfil_cloud_storage_new_pos')
    neg = load_vector('top40', 'exfil_cloud_storage_new_neg')
    assert any(r.id == 'exfil_cloud_storage_new' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'exfil_cloud_storage_new' for r in CORRELATION_RULES.evaluate(neg))


def test_exfil_paste_bin_pos_neg():
    pos = load_vector('top40', 'exfil_paste_bin_pos')
    neg = load_vector('top40', 'exfil_paste_bin_neg')
    assert any(r.id == 'exfil_paste_bin' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'exfil_paste_bin' for r in CORRELATION_RULES.evaluate(neg))


def test_imp_shadowcopy_delete_pos_neg():
    pos = load_vector('top40', 'imp_shadowcopy_delete_pos')
    neg = load_vector('top40', 'imp_shadowcopy_delete_neg')
    assert any(r.id == 'imp_shadowcopy_delete' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'imp_shadowcopy_delete' for r in CORRELATION_RULES.evaluate(neg))


def test_imp_encrypt_pattern_canary_pos_neg():
    pos = load_vector('top40', 'imp_encrypt_pattern_canary_pos')
    neg = load_vector('top40', 'imp_encrypt_pattern_canary_neg')
    assert any(r.id == 'imp_encrypt_pattern_canary' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'imp_encrypt_pattern_canary' for r in CORRELATION_RULES.evaluate(neg))


def test_disc_ad_enum_pos_neg():
    pos = load_vector('top40', 'disc_ad_enum_pos')
    neg = load_vector('top40', 'disc_ad_enum_neg')
    assert any(r.id == 'disc_ad_enum' for r in CORRELATION_RULES.evaluate(pos))
    assert not any(r.id == 'disc_ad_enum' for r in CORRELATION_RULES.evaluate(neg))

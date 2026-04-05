from src.core.hunt.evidence_envelope import EvidenceEnvelope
from src.core.hunt.lanes.email_bec import build as build_email_bec


def test_double_extension_and_rtlo():
    env = EvidenceEnvelope({'id':'evt-att-1'})
    env.event = {'file_name': 'invoice.pdf.exe', 'attachment_type': 'application/octet-stream'}
    env.headers = {'From':'attacker@evil.com'}
    env.body = 'See attached'
    lane = build_email_bec()
    lane(env)
    f = env.all_factors
    assert 'email:double_extension' in f

    # RTLO
    env2 = EvidenceEnvelope({'id':'evt-att-2'})
    env2.event = {'file_name': 'report\u202eexe.pdf', 'attachment_type': 'application/octet-stream'}
    env2.headers = {'From':'attacker@evil.com'}
    env2.body = 'See attached'
    lane(env2)
    f2 = env2.all_factors
    assert 'email:rtlo_filename' in f2


def test_iso_and_executable_in_archive_and_password():
    env = EvidenceEnvelope({'id':'evt-att-3'})
    env.event = {
        'file_name': 'backup.iso',
        'attachment_type': 'application/x-iso9660-image',
        'attachment_list': ['readme.txt','danger.exe'],
        'attachment_meta': {'attachment_encrypted': True}
    }
    env.headers = {'From':'attacker@evil.com'}
    env.body = 'See attached encrypted backup. Password: hunter2'
    lane = build_email_bec()
    lane(env)
    f = env.all_factors
    assert 'email:iso_img_attachment' in f
    assert 'email:executable_in_archive' in f
    assert 'email:password_protected_archive' in f

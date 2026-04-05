from src.core.redaction import scrub_text, scrub_record, classify_evidence


def test_scrub_text_email_phone_ip():
    s = 'Contact me at alice@example.com or +1-415-555-1234 from 10.0.0.1'
    out = scrub_text(s)
    assert '[email]' in out
    assert '[phone]' in out
    assert '[ip]' in out


def test_scrub_record_nested():
    rec = {'user':'bob@example.com','nums':['555-123-4567','safe'],'nested':{'ip':'192.168.1.1'}}
    out = scrub_record(rec)
    assert out['user'] == '[email]'
    assert out['nums'][0] == '[phone]'
    assert out['nested']['ip'] == '[ip]'


def test_classification_policy():
    cls, dest = classify_evidence({'text':'alice@example.com'})
    assert cls == 'CONFIDENTIAL' and dest == 'ticket'
    cls2, dest2 = classify_evidence({'text':'no pii'})
    assert cls2 == 'INTERNAL' and dest2 == 'teams'

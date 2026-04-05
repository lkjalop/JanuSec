from src.domains.email.attachment_analyzer import analyze_attachment


def test_detect_macro_by_extension_and_signature():
    content = b'PK\x03\x04...vbaProject.bin...'
    res = analyze_attachment(content, 'report.docm')
    assert res['is_macro'] is True
    assert res['suspicious'] is True


def test_extension_mismatch():
    content = b'PK\x03\x04ZIPCONTENT'
    res = analyze_attachment(content, 'image.jpg')
    assert res['extension_mismatch'] is True

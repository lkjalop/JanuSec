from src.modules.scan_detector import ScanDetector

def test_scan_detector_vertical():
    sd = ScanDetector()
    src = '10.0.0.1'
    dst = '10.0.0.5'
    # feed many ports
    for p in range(1, 25):
        res = sd.observe(src, dst, p)
    assert res['scan_type'] in ('vertical','horizontal')
    assert res['scan_score'] > 0

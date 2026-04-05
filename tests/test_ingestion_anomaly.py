import time
from src.core.monitoring.ingestion_anomaly import IngestionAnomalyDetector


def test_record_and_summary(tmp_path):
    det = IngestionAnomalyDetector(persist_dir=str(tmp_path))
    det.record_event('srcA')
    summary = det.get_summary()
    assert 'srcA' in summary.get('last_seen', {})
    assert 'srcA' in summary.get('ewma_counts', {})


def test_detect_gaps(tmp_path):
    det = IngestionAnomalyDetector(persist_dir=str(tmp_path))
    now = time.time()
    # seed last_seen with an old timestamp
    det.state['last_seen'] = {'old_src': now - 1000, 'fresh_src': now}
    det._save()
    gaps = det.detect_gaps(stale_threshold_seconds=300)
    assert any(g.get('source') == 'old_src' for g in gaps)
    assert not any(g.get('source') == 'fresh_src' for g in gaps)

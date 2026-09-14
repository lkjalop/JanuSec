import logging
from core.logging_utils import log_backoff

def test_log_backoff_emission_schedule(caplog):
    logger = logging.getLogger('test_backoff')
    caplog.set_level(logging.WARNING)
    emitted = []
    def hook(count, msg):
        emitted.append(count)
    # first_n=2, ratio=5 -> emit counts 1,2 then every 5th after
    for i in range(1,21):
        log_backoff(logger, 'k', logging.WARNING, 'hello', first_n=2, ratio=5, emit=hook)
    # Expect emissions at 1,2,7,12,17
    assert emitted == [1,2,7,12,17]
    # Ensure log records present for those counts
    counts_logged = [r.message for r in caplog.records]
    assert len(counts_logged) == 5

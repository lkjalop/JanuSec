import os

def enable_deterministic_mode():
    os.environ["HOPGRAPH_DETERMINISTIC"] = os.getenv("HOPGRAPH_DETERMINISTIC", "1")
    os.environ["FAST_TEST_MODE"] = os.getenv("FAST_TEST_MODE", "1")

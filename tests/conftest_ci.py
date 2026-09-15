import os


def pytest_configure(config):
    # In CI environments, force deterministic LLM mock to avoid external calls
    if os.environ.get('CI'):
        os.environ.setdefault('LLM_MOCK', '1')

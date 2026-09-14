import os
import vcr
import pytest


@pytest.fixture(scope='session')
def vcr_config_dir():
    return os.path.join(os.path.dirname(__file__), 'integration', 'cassettes')


@pytest.fixture
def vcr_cassette(request, vcr_config_dir):
    """Provide a vcr cassette wrapper for tests. Usage:

    def test_x(vcr_cassette):
        with vcr_cassette('my_test.yml'):
            ...
    """
    def _cname(name):
        path = os.path.join(vcr_config_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        return vcr.VCR(record_mode='once', cassette_library_dir=vcr_config_dir)

    return _cname

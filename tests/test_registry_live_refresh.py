import os
import tempfile
import time

os.environ.setdefault('PLATFORM_LITE_INIT','1')
from src.connectors.registry import set_policy, register, get, set_config, get_config, load_policies
from src.connectors.sdk import BaseConnector

class DummyConnector(BaseConnector):
    def __init__(self, rate_limiter=None, allow_hosts=None):
        self.rate_limiter = rate_limiter
        self.allow_hosts = set(allow_hosts or [])
        self.config = {}
    def execute(self, *args, **kwargs):
        return {'ok': True}
    def set_config(self, cfg):
        self.config = cfg


def test_live_policy_apply(tmp_path):
    # clean policies file
    pol = tmp_path / 'policies.json'
    os.environ['CONNECTORS_POLICY_PATH'] = str(pol)
    if pol.exists():
        pol.unlink()

    # register connector
    register('dummy', DummyConnector(rate_limiter=None, allow_hosts=set()))
    # set policy
    p = {'enabled': True, 'rate_limit': {'rate_per_second': 2.0, 'burst': 4.0}, 'allow_hosts': ['example.com']}
    set_policy('dummy', p)
    # ensure applied
    c = get('dummy')
    assert hasattr(c, 'allow_hosts')
    assert 'example.com' in c.allow_hosts


def test_config_set_and_notify(tmp_path):
    cfg_path = tmp_path / 'cfgs.json'
    os.environ['CONNECTORS_CONFIG_PATH'] = str(cfg_path)
    if cfg_path.exists():
        cfg_path.unlink()
    register('dummy2', DummyConnector())
    cfg = {'url': 'https://api.example', 'enabled': True}
    set_config('dummy2', cfg)
    # read back
    got = get_config('dummy2')
    assert got['url'] == 'https://api.example'
    c = get('dummy2')
    assert c.config == cfg

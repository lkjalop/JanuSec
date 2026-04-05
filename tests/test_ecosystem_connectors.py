import pytest

from src.collectors.scanners.ecosystem_connectors import MavenGradleConnector, RubyGemsConnector, GoModulesConnector, CargoConnector

@pytest.mark.asyncio
async def test_maven_gradle_connector():
    c = MavenGradleConnector()
    out = await c.run_scan('.')
    assert 'components' in out and len(out['components']) >= 2

@pytest.mark.asyncio
async def test_rubygems_connector():
    c = RubyGemsConnector()
    out = await c.run_scan('.')
    assert 'components' in out and len(out['components']) >= 2

@pytest.mark.asyncio
async def test_gomod_connector():
    c = GoModulesConnector()
    out = await c.run_scan('.')
    assert 'components' in out and len(out['components']) >= 2

@pytest.mark.asyncio
async def test_cargo_connector():
    c = CargoConnector()
    out = await c.run_scan('.')
    assert 'components' in out and len(out['components']) >= 2

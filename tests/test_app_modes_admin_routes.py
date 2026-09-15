import os
import importlib
from src.api.app import create_app


def _has_arc_route(app):
    return any(getattr(r, 'path', '').startswith('/api/v1/admin/arc') for r in app.router.routes)


def test_create_app_in_modes():
    # test mode
    app_test = create_app({'mode': 'test'})
    assert _has_arc_route(app_test)

    # lite mode via env
    os.environ['PLATFORM_LITE_INIT'] = '1'
    app_lite = create_app({'mode': 'lite'})
    assert _has_arc_route(app_lite)
    os.environ.pop('PLATFORM_LITE_INIT', None)

    # prod mode
    app_prod = create_app({'mode': 'prod'})
    assert _has_arc_route(app_prod)

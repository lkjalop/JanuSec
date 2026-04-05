import os
import pytest

# ensure lite init is used by default for these tests
os.environ.setdefault('PLATFORM_LITE_INIT', '1')

from src.api import runtime_state


def test_lite_mode_no_background_workers():
    """Micro test to ensure lite-mode does not start persistent background
    services during initialize_platform_components.
    """
    # In lite mode the learner and dlq should be unset/None
    assert getattr(runtime_state, 'learner', None) is None
    assert getattr(runtime_state, 'dlq', None) is None

"""Package initializer for src.core.config

Expose helper functions used by the application such as `get_settings`
and LLM settings helpers.
"""
try:
	# attempt absolute import to access top-level config.get_settings
	from src.core import config as _top_config
except Exception:
	try:
		from .. import config as _top_config
	except Exception:
		_top_config = None
from .llm_settings_store import load_settings, save_settings
from .runtime_thresholds import *
from .tenant_overrides import *

if _top_config and hasattr(_top_config, 'get_settings'):
	get_settings = _top_config.get_settings
else:
	def get_settings():
		return {}

__all__ = ['get_settings', 'load_settings', 'save_settings']

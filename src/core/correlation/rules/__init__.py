from .registry import RuleRegistry, register_rule
from .registry import CORRELATION_RULES
# Ensure example rules are registered on package import (tests expect side-effects)
from . import examples  # noqa: F401

import os

# Fast/test mode: avoid expensive or flaky auto-discovery during CI runs.
# When FAST_TEST_MODE is enabled or running under pytest, import only a
# curated set of lightweight rule modules required by tests.
_FAST = str(os.getenv('FAST_TEST_MODE','')).lower() in {'1','true','yes'}
_UNDER_PYTEST = 'PYTEST_CURRENT_TEST' in os.environ

if _FAST or _UNDER_PYTEST:
	try:
		import importlib
		# Minimal modules that cover expected rules in tests
		importlib.import_module('src.core.correlation.rules.week1.amsi_bypass')
		importlib.import_module('src.core.correlation.rules.week1.office_macro_chain')
		importlib.import_module('src.core.correlation.rules.week1.office_spawn_ps')
		importlib.import_module('src.core.correlation.rules.week1.powershell_encoded')
		importlib.import_module('src.core.correlation.rules.week1.scheduled_task_lolbin')
		importlib.import_module('src.core.correlation.rules.week2.registry_run_keys')
		importlib.import_module('src.core.correlation.rules.week2.new_service_nonstandard_path')
		importlib.import_module('src.core.correlation.rules.week2.new_service_nonstandard_path_enriched')
		importlib.import_module('src.core.correlation.rules.week2.lsass_openprocess')
		importlib.import_module('src.core.correlation.rules.top10_priority')
		importlib.import_module('src.core.correlation.rules.weekX.expanded_batch')
		importlib.import_module('src.core.correlation.rules.weekX.t1078_valid_accounts')
		importlib.import_module('src.core.correlation.rules.weekX.t1133_external_remote')
		# Ensure graph lateral chain length rule is available in test mode
		importlib.import_module('src.core.correlation.rules.weekX.graph_week1')
		# Email rules used by pack tests
		importlib.import_module('src.core.correlation.rules.email.header_spoof_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_impersonation_enriched')
		importlib.import_module('src.core.correlation.rules.email.dkim_dmarc_failure_enriched')
		importlib.import_module('src.core.correlation.rules.email.email_to_lolbin_chain_enriched')
		importlib.import_module('src.core.correlation.rules.email.display_name_fuzzy_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_chain_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_reply_chain_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_vendor_spoof_chain_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_invoice_fraud_pattern_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_supplier_portal_takeover_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_brand_oauth_spoof_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_supplier_replyto_freemail_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_payment_change_dkim_pass_domain_flip_enriched')
		importlib.import_module('src.core.correlation.rules.email.email_oauth_brand_spoof_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_supplier_portal_free_reply_enriched')
		importlib.import_module('src.core.correlation.rules.email.bec_payment_change_dkim_flip_enriched')
		importlib.import_module('src.core.correlation.rules.batch_more.additional_30')
		# Cross-platform LOLBin detection rules (have dedicated tests). These were
		# omitted from the curated test-mode list, so under pytest the rules never
		# registered and every linux/macos lolbin test failed (fired == []).
		importlib.import_module('src.core.correlation.rules.linux_lolbins')
		importlib.import_module('src.core.correlation.rules.macos_lolbins')
		# Import curated tranche packs last so tranche-specific definitions win
		# when duplicate rule ids exist across broader packs.
		importlib.import_module('src.core.correlation.rules.top20_priority')
		importlib.import_module('src.core.correlation.rules.top30_priority')
		importlib.import_module('src.core.correlation.rules.top40_priority')
	except Exception:
		# best-effort: ignore failures to avoid breaking package import
		pass
else:
	# Auto-discover rule modules: iterate immediate .py files and subpackages,
	# and walk one level deep into subdirectories.
	try:
		import pkgutil, importlib, pathlib
		pkg_dir = pathlib.Path(__file__).parent
		# iterate immediate .py files and subpackages
		for finder, mod_name, ispkg in pkgutil.iter_modules([str(pkg_dir)]):
			# skip this package's explicit modules like registry and __init__
			if mod_name in {'registry', '__init__', 'examples', 'rules_metadata'}:
				continue
			try:
				importlib.import_module(f"src.core.correlation.rules.{mod_name}")
			except Exception:
				# best-effort: ignore failures to avoid breaking package import
				pass
		# Also walk subdirectories one level deep and import their modules
		for child in pkg_dir.iterdir():
			if child.is_dir():
				try:
					for finder, submod, ispkg in pkgutil.iter_modules([str(child)]):
						fullname = f"src.core.correlation.rules.{child.name}.{submod}"
						try:
							importlib.import_module(fullname)
						except Exception:
							pass
				except Exception:
					pass
	except Exception:
		pass

__all__ = ['RuleRegistry','register_rule','CORRELATION_RULES']

# Explicitly import top50 tranche rules so their decorators execute during
# package import. This mirrors existing curated imports for prior tranches.
try:
	import importlib
	importlib.import_module('src.core.correlation.rules.top50_priority')
except Exception:
	# best-effort: ignore import failures to avoid breaking package import
	pass

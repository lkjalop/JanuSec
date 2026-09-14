import importlib, sys, os
# Ensure project root is on sys.path
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

modules = [
 'src.repositories.audit_repo',
 'src.repositories.playbook_repo',
 'src.reporting.feedback_hooks',
 'src.api.report_endpoints',
 'src.reporting.persona_views'
]
errs = False
for m in modules:
    try:
        importlib.import_module(m)
        print('OK', m)
    except Exception as e:
        print('ERR', m, e)
        errs = True
if errs:
    sys.exit(2)

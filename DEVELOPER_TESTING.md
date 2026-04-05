Developer testing and run instructions

Always ensure Python can import application modules under `src/` by setting `PYTHONPATH=src` when running tests or scripts from the project root.

PowerShell (recommended on Windows):

```powershell
# One-line: run pytest with PYTHONPATH set for this session
$env:PYTHONPATH = 'src'; python -m pytest -q

# One-off import check
$env:PYTHONPATH = 'src'; python -c "import importlib; m=importlib.import_module('core.metrics.registry'); print('OK', m.__name__)"
```

Bash / macOS / Linux:

```bash
# Run tests with src on PYTHONPATH
PYTHONPATH=src python -m pytest -q

# One-off import check
PYTHONPATH=src python -c "import importlib; m=importlib.import_module('core.metrics.registry'); print('OK', m.__name__)"
```

Notes:
- CI must also set `PYTHONPATH=src` in the job steps before running tests or the application.
- Alternately, install the package into the test environment (pip install -e .) if you prefer not to set PYTHONPATH.

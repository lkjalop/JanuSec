import subprocess, sys, pathlib, time, os
p = pathlib.Path('.')
files = []
# Prefer tests under the `tests/` directory to avoid scanning venv or site-packages
tests_dir = p / 'tests'
if tests_dir.exists() and tests_dir.is_dir():
    for root, dirs, filenames in os.walk(str(tests_dir), topdown=True):
        dirs[:] = [d for d in dirs if ('.venv' not in d.lower() and d.lower() not in ('__pycache__', '.git'))]
        for name in filenames:
            if name.startswith('test_') and name.endswith('.py'):
                files.append(os.path.join(root, name))
# Also include any root-level test_*.py files
for pth in p.glob('test_*.py'):
    files.append(str(pth))
files = sorted(set(files))
print('Found', len(files), 'test files')
print('\nFirst 20 discovered test files:')
for i,f in enumerate(files[:20], start=1):
    print(f'{i:2d}: {f}')
TIMEOUT = 120
failed_files = []
timeouts = []
for f in files:
    print('\n=== Running', f)
    try:
        start = time.time()
        cp = subprocess.run([sys.executable, '-m', 'pytest', '-q', f], capture_output=True, text=True, timeout=TIMEOUT)
        dur = time.time()-start
        print(cp.stdout)
        if cp.stderr:
            print('--- STDERR ---')
            print(cp.stderr)
        print('Exit:', cp.returncode, f'in {dur:.1f}s')
        # If pytest collected zero items (benign), continue to next file
        out = (cp.stdout or '') + (cp.stderr or '')
        if 'collected 0 items' in out.lower():
            print('No tests collected in', f, '- continuing')
            continue
        if cp.returncode != 0:
            print('FAILED:', f, 'exit', cp.returncode)
            with open('tmp_failed_test_output.txt', 'a', encoding='utf-8') as fh:
                fh.write(f"\n\n--- FAILED: {f} (exit {cp.returncode}) ---\n")
                fh.write(cp.stdout or '')
                fh.write('\n--- STDERR ---\n')
                fh.write(cp.stderr or '')
            failed_files.append((f, cp.returncode))
            # continue to next file to surface other failures/timeouts
            continue
    except subprocess.TimeoutExpired:
        print('TIMEOUT:', TIMEOUT, 'seconds for', f)
        with open('tmp_failed_test_output.txt', 'a', encoding='utf-8') as fh:
            fh.write(f"\n\n--- TIMEOUT: {f} (>{TIMEOUT}s) ---\n")
        timeouts.append(f)
        # continue to next file
        continue

print('\nRun complete. Summary:')
print('Failures:', len(failed_files))
for ff, rc in failed_files[:20]:
    print(' -', ff, 'exit', rc)
print('Timeouts:', len(timeouts))
for t in timeouts[:20]:
    print(' -', t)

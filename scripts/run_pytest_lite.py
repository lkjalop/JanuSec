import os, subprocess, sys

env = os.environ.copy()
env['PLATFORM_LITE_INIT'] = '1'
env['FAST_TEST_MODE'] = '1'
env['TEST_HELPERS_ENABLED'] = '1'
cmd = [sys.executable, '-m', 'pytest', '-q']
print('Running:', ' '.join(cmd))
res = subprocess.run(cmd, env=env)
print('Exit code', res.returncode)
sys.exit(res.returncode)

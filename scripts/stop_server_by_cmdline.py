"""Stop server processes by matching substrings in their command line.

Usage: python scripts/stop_server_by_cmdline.py

This prefers to use psutil when available for graceful termination and
falls back to inspecting netstat/process IDs and calling taskkill.
"""
import subprocess
import sys

try:
    import psutil
except Exception:
    psutil = None

TARGET_SUBSTRINGS = ['src.api.app', 'start_test_server.ps1', 'uvicorn']

def find_pids():
    pids = set()
    if psutil:
        for p in psutil.process_iter(['pid', 'cmdline']):
            try:
                cmd = ' '.join(p.info.get('cmdline') or [])
                if any(s in cmd for s in TARGET_SUBSTRINGS):
                    pids.add(p.info['pid'])
            except Exception:
                continue
        return sorted(pids)

    # fallback: use netstat to find listeners on :8080
    try:
        out = subprocess.check_output(['netstat', '-ano'], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if ':8080 ' in line:
                parts = line.split()
                if parts:
                    try:
                        pids.add(int(parts[-1]))
                    except Exception:
                        continue
    except Exception:
        pass
    return sorted(pids)

def stop_pid(pid):
    try:
        if psutil:
            p = psutil.Process(pid)
            print('terminating', pid)
            p.terminate()
            try:
                p.wait(timeout=5)
                print('terminated', pid)
            except Exception:
                print('kill', pid)
                p.kill()
        else:
            print('taskkill', pid)
            subprocess.check_call(['taskkill', '/PID', str(pid), '/F'])
    except Exception as e:
        print('failed to stop', pid, e)

def main():
    pids = find_pids()
    if not pids:
        print('no server PIDs found')
        return 0
    for pid in pids:
        stop_pid(pid)
    return 0

if __name__ == '__main__':
    sys.exit(main())

import os


def crash_exit():
    """Forcefully exit the current process to simulate a worker crash."""
    os._exit(1)

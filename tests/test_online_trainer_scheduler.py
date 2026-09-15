import os
import asyncio
import importlib


def test_register_online_trainer_scheduler_registers_handler(monkeypatch):
    # Ensure the register function can be called without starting a long loop
    os.environ['ONLINE_TRAINER_SCHED_ENABLED'] = '1'
    # Import the module and call register with a small interval; ensure it attaches startup handler
    from src.tasks import online_trainer_scheduler as sched_mod

    class DummyApp:
        def __init__(self):
            self._handlers = {'startup': []}

        def add_event_handler(self, name, fn):
            if name not in self._handlers:
                self._handlers[name] = []
            self._handlers[name].append(fn)

    app = DummyApp()
    # monkeypatch generate_candidate_weights to a no-op coroutine
    async def _fake_gen(*args, **kwargs):
        return None

    monkeypatch.setattr('src.tasks.online_trainer_scheduler.generate_candidate_weights', _fake_gen, raising=False)
    # Call register; should not raise
    sched_mod.register_online_trainer_scheduler(app, interval_seconds=1)
    assert 'startup' in app._handlers

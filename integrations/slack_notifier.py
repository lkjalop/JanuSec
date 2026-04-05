# Minimal shim to satisfy imports in core.actions.dispatcher
class SlackNotifier:
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url
    def send(self, message: str):
        # noop for tests
        return True

__all__ = ['SlackNotifier']

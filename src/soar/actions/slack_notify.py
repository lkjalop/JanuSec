from __future__ import annotations

import os
from typing import Any, Dict

from .. import BaseAction, register


class SlackNotifyAction(BaseAction):
    name = 'slack_notify'
    description = 'Send a Slack-style notification (placeholder)'
    timeout_seconds = 5.0

    async def run(self, context: dict[str, Any]) -> dict[str, Any]:
        channel = context.get('channel') or '#general'
        text = context.get('text') or 'No message'
        # Placeholder: real implementation would enqueue or call Slack API
        if os.getenv('PLAYBOOK_VERBOSE_LOG'):  # optional debug hook
            print(f'[PLAYBOOK] SlackNotify -> {channel}: {text}')
        return {'sent': True, 'channel': channel, 'length': len(text)}

register(SlackNotifyAction())

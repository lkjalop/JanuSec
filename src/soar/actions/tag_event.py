from __future__ import annotations

from typing import Any, Dict

from .. import BaseAction, register


class TagEventAction(BaseAction):
    name = 'tag_event'
    description = 'Attach a tag to the working context event.'
    timeout_seconds = 2.0

    async def run(self, context: dict[str, Any]) -> dict[str, Any]:
        tag = context.get('tag') or 'generic'
        tags = context.setdefault('event_tags', [])
        if tag not in tags:
            tags.append(tag)
        # Return the updated tags so the engine can merge them into the outer context
        return {'tagged': tag, 'total_tags': len(tags), 'event_tags': list(tags)}

register(TagEventAction())

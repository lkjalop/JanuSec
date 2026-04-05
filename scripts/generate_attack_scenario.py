from __future__ import annotations

import time
from typing import List, Dict, Any


def make_identity_escalation(user: str = 'alice@corp.com') -> List[Dict[str, Any]]:
    now = time.time()
    return [
        {'user': user, 'src_host': 'ws-1', 'dest_host': 'ws-1', 'event_type': 'login', 'action': 'login', 'ts': now},
        {'user': user, 'src_host': 'ws-1', 'dest_host': 'server-1', 'event_type': 'login', 'action': 'login', 'ts': now+30},
        {'user': user, 'action': 'assume_role', 'new_role': 'Admin', 'ts': now+60},
    ]


if __name__ == '__main__':  # pragma: no cover
    import json
    print(json.dumps(make_identity_escalation(), indent=2))


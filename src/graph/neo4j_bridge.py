from __future__ import annotations
import os
from typing import Dict, Any

try:
    from neo4j import GraphDatabase
except Exception:
    GraphDatabase = None  # pragma: no cover

NEO_URI = os.getenv('NEO4J_URI')
NEO_USER = os.getenv('NEO4J_USER')
NEO_PASS = os.getenv('NEO4J_PASS')


def _get_driver():
    if not GraphDatabase or not NEO_URI:
        return None
    return GraphDatabase.driver(NEO_URI, auth=(NEO_USER, NEO_PASS))


def upsert_event_node(event: Dict[str, Any]):
    drv = _get_driver()
    if not drv:
        return False
    with drv.session() as sess:
        ev_id = event.get('event_id')
        principal = (event.get('actor') or {}).get('principal_id')
        # create event node and relation to principal
        sess.run("MERGE (e:Event {id:$id}) SET e += $props", {'id': ev_id, 'props': {'ts': event.get('ts'), 'domain': event.get('domain')}})
        if principal:
            sess.run("MERGE (p:Principal {id:$pid})", {'pid': principal})
            sess.run("MATCH (e:Event {id:$id}), (p:Principal {id:$pid}) MERGE (p)-[:TRIGGERED]->(e)", {'id': ev_id, 'pid': principal})
    return True


def upsert_resource_node(resource_id: str, props: Dict[str, Any]):
    drv = _get_driver()
    if not drv:
        return False
    with drv.session() as sess:
        sess.run("MERGE (r:Resource {id:$id}) SET r += $props", {'id': resource_id, 'props': props})
    return True


__all__ = ['upsert_event_node','upsert_resource_node']

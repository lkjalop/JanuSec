"""Entity Resolution layer — host -> owner via inventory / co-occurrence / naming."""
from __future__ import annotations

from src.core.entity_resolver import EntityResolver, resolve_entities


def test_cooccurrence_learns_host_owner():
    rows = [{"hostname": "sfl-lt-0442", "user_canonical": "rachel.nakamura"} for _ in range(10)]
    r = EntityResolver().build_from_rows(rows)
    owner, method = r.resolve_owner("sfl-lt-0442")
    assert owner == "rachel.nakamura" and method == "cooccurrence"


def test_naming_heuristic_when_no_cooccurrence():
    # VESPER case: identity rows (user, no host) + endpoint rows (host, no user) never
    # co-occur. The hostname convention ws-<firstname>-NN bridges them.
    rows = [
        {"user_canonical": "martin.chen"},          # identity plane (no host)
        {"hostname": "ws-martin-01", "event_name": "certutil"},  # host plane (no user)
    ]
    r = EntityResolver().build_from_rows(rows)
    owner, method = r.resolve_owner("ws-martin-01")
    assert owner == "martin.chen" and method == "naming"


def test_inventory_beats_cooccurrence_and_naming():
    rows = [{"hostname": "ws-martin-01", "user_canonical": "someone.else"} for _ in range(5)]
    r = EntityResolver(asset_inventory={"ws-martin-01": {"owner": "martin.chen", "asset_class": "workstation"}})
    r.build_from_rows(rows)
    owner, method = r.resolve_owner("ws-martin-01")
    assert owner == "martin.chen" and method == "inventory"
    assert r.asset_class("ws-martin-01") == "workstation"


def test_shared_host_not_mis_owned():
    # A jump/shared host used by many users should NOT be attributed to one owner.
    rows = ([{"hostname": "jump01", "user_canonical": f"u{i}"} for i in range(10)])
    r = EntityResolver().build_from_rows(rows)
    owner, _ = r.resolve_owner("jump01")
    assert owner is None


def test_resolve_row_backfills_host_only_rows_only():
    rows = [
        {"user_canonical": "martin.chen"},
        {"hostname": "ws-martin-01", "dst": "evil"},        # host-only -> should inherit
        {"hostname": "ws-martin-01", "user_canonical": "real.user"},  # has user -> untouched
    ]
    resolve_entities(rows)
    assert rows[1]["user_canonical"] == "martin.chen"
    assert rows[1]["_entity_owner_method"] == "naming"
    assert rows[2]["user_canonical"] == "real.user"   # not overridden

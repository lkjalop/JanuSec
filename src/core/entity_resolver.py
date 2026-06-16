"""Entity Resolution — the single layer that answers "who/what is this".

The recurring breakage (exfil not stitched to the actor, no-user network 'breaches',
host-only rows that never reach the identity campaign) all traces to one root: "who
is this entity" was implemented four separate times (entities.py, streaming_ingest
_canonical_user, identity_hopgraph, cluster_merge pivots) with no shared contract,
and NONE resolved host -> owner.

This is the industry-standard fix (Chronicle's Entity Context Graph, Exabeam, Sentinel
UEBA, DataBee): one Entity Resolution layer, fed by identity providers + an operator
asset inventory (CMDB) + data co-occurrence + naming heuristics, that backfills the
canonical actor onto host/IP-only rows so cross-domain telemetry stitches to one actor.

Resolution priority for host -> owner:
  1. operator asset inventory (authoritative CMDB)         — explicit, highest trust
  2. data co-occurrence (rows carrying BOTH host + user)    — learned from the batch
  3. hostname naming convention (ws-<firstname>-NN)         — heuristic fallback

This is a BATCH pass (normalize per-row -> resolve over the batch -> cluster), because
host->owner can only be learned by looking across rows.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass


@dataclass(frozen=True)
class Entity:
    """A resolved entity. ``id`` is the stable cross-source key (e.g. 'user:martin.chen')
    that correlation pivots on instead of raw fields."""
    id: str
    type: str            # user | host | ip | session | token | device
    value: str
    owner: str | None = None        # for host/ip/device: the resolved owning user
    asset_class: str | None = None  # hypervisor | server | workstation | edge | crown_jewel
    idp_verified: bool = False


_SKIP_USERS = frozenset({"", "-", "n/a", "na", "unknown", "system", "root", "anonymous"})
# ws-martin-01 / lt-anna-12 / DESKTOP-james — capture the name token.
_HOST_NAME_RE = re.compile(r"(?:ws|wks|lt|laptop|desktop|pc|host)[-_]([a-z]{3,})", re.I)


def _lower(v) -> str:
    return str(v or "").strip().lower()


class EntityResolver:
    def __init__(self, asset_inventory: dict | None = None) -> None:
        # asset_inventory: {hostname_lower: {"owner": user, "asset_class": cls}}
        self._asset: dict[str, dict] = {
            _lower(h): v for h, v in (asset_inventory or {}).items()
        }
        self._host_user: dict[str, str] = {}     # learned host -> owner (co-occurrence)
        self._firstname_user: dict[str, str] = {}  # 'martin' -> 'martin.chen' (for heuristic)

    # ── Learning pass ─────────────────────────────────────────────────────────
    def build_from_rows(self, rows: list[dict]) -> "EntityResolver":
        host_users: dict[str, Counter] = defaultdict(Counter)
        for r in rows:
            user = _lower(r.get("user_canonical") or r.get("user"))
            host = _lower(r.get("hostname") or r.get("host"))
            if user and user not in _SKIP_USERS:
                first = user.split(".")[0].split("@")[0]
                if len(first) >= 3:
                    self._firstname_user.setdefault(first, user)
                if host:
                    host_users[host][user] += 1
        # A host's owner = its dominant non-skip user, but only if clearly dominant
        # (>=60% of its identified rows) so shared/jump hosts don't get mis-owned.
        for host, ctr in host_users.items():
            top, n = ctr.most_common(1)[0]
            if n >= max(3, 0.6 * sum(ctr.values())):
                self._host_user[host] = top
        return self

    # ── Resolution ────────────────────────────────────────────────────────────
    def resolve_owner(self, host: str) -> tuple[str | None, str]:
        """Return (owner, method) for a host: inventory > co-occurrence > naming."""
        h = _lower(host)
        if not h:
            return None, "none"
        if h in self._asset and self._asset[h].get("owner"):
            return _lower(self._asset[h]["owner"]), "inventory"
        if h in self._host_user:
            return self._host_user[h], "cooccurrence"
        m = _HOST_NAME_RE.search(h)
        if m:
            token = m.group(1).lower()
            if token in self._firstname_user:
                return self._firstname_user[token], "naming"
        return None, "none"

    def asset_class(self, host: str) -> str | None:
        h = _lower(host)
        if h in self._asset:
            return self._asset[h].get("asset_class")
        return None

    def resolve_row(self, row: dict) -> dict:
        """Backfill the owning user onto a host-only row, in place. Returns the row.
        Stamps _entity_owner + _entity_owner_method for provenance/grounding; only sets
        user_canonical when the row has a host but no user (never overrides a real user)."""
        host = _lower(row.get("hostname") or row.get("host"))
        if not host:
            return row
        ac = self.asset_class(host)
        if ac and not row.get("asset_class"):
            row["asset_class"] = ac
        existing_user = _lower(row.get("user_canonical") or row.get("user"))
        if existing_user and existing_user not in _SKIP_USERS:
            return row  # already attributed — don't override
        owner, method = self.resolve_owner(host)
        if owner:
            row["user_canonical"] = owner
            row["_entity_owner"] = owner
            row["_entity_owner_method"] = method
        return row


def resolve_entities(rows: list[dict], asset_inventory: dict | None = None) -> list[dict]:
    """Batch entity resolution: learn host->owner from the rows (+ optional operator
    asset inventory), then backfill the owner onto host-only rows so cross-domain
    telemetry stitches to one actor. Idempotent; mutates rows in place and returns them."""
    resolver = EntityResolver(asset_inventory).build_from_rows(rows)
    for r in rows:
        resolver.resolve_row(r)
    return rows

"""Explicitly authorized collection and append-only persistence of infrastructure truth."""

from __future__ import annotations

import asyncio
import datetime as dt
from dataclasses import dataclass
from typing import Any

from .asymmetric_signing import DigestSigner
from .snapshot_connectors import SignedSnapshotConnector


@dataclass(slots=True)
class AuthorizedCollector:
    connector: SignedSnapshotConnector
    tenant_id: str
    version: str
    validity_seconds: int
    signer: DigestSigner
    explicitly_authorized: bool = False

    async def collect_once(self) -> dict[str, Any]:
        if not self.explicitly_authorized:
            raise PermissionError("infrastructure_collection_requires_explicit_authorization")
        now = dt.datetime.now(dt.timezone.utc)
        snapshot = await asyncio.to_thread(
            self.connector.collect,
            tenant_id=self.tenant_id,
            version=self.version,
            valid_from=now.isoformat(),
            valid_to=(now + dt.timedelta(seconds=max(1, self.validity_seconds))).isoformat(),
            signer=self.signer,
        )
        from src.repositories.infrastructure_truth_repo import append_snapshot

        persistence = await append_snapshot(snapshot)
        return {"snapshot": snapshot, "persistence": persistence}


async def run_authorized_collector(
    collector: AuthorizedCollector, *, interval_seconds: float, stop: asyncio.Event,
) -> None:
    """Run a collector until stopped; authorization is checked on every cycle."""

    while not stop.is_set():
        await collector.collect_once()
        try:
            await asyncio.wait_for(stop.wait(), timeout=max(1.0, interval_seconds))
        except TimeoutError:
            pass


__all__ = ["AuthorizedCollector", "run_authorized_collector"]

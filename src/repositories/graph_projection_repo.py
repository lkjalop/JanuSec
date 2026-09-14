"""Append-only persistence for authoritative typed graph projections."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any

from src.core.evidence_contract.graph_projection import GraphProjectionReceipt
from src.core.evidence_contract.records import canonical_hash
from src.core.evidence_contract.spatiotemporal import validate_tenant_graph
from src.db.database import DatabaseNotAvailable, get_pool, init_pool

_TABLES = {
    "node": "evidence_graph_nodes",
    "edge": "evidence_graph_edges",
    "receipt": "graph_view_receipts",
}


async def _connection():
    try:
        pool = await get_pool()
    except DatabaseNotAvailable:
        await init_pool()
        pool = await get_pool()
    return pool.acquire()


def _sqlite(conn: Any) -> bool:
    return conn.__class__.__name__ == "SQLiteConnectionProxy"


def _canonical_payload(value: Any) -> str:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


async def ensure_schema() -> None:
    async with await _connection() as conn:
        json_type = "TEXT" if _sqlite(conn) else "JSONB"
        timestamp = "REAL NOT NULL" if _sqlite(conn) else "TIMESTAMPTZ NOT NULL DEFAULT NOW()"
        for table, id_column in (("evidence_graph_nodes", "node_record_id"), ("evidence_graph_edges", "edge_record_id")):
            await conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {table} (
                  {id_column} TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
                  projection_id TEXT NOT NULL, semantic_id TEXT NOT NULL, content_hash TEXT NOT NULL,
                  record_json {json_type} NOT NULL, appended_at {timestamp})
            """)
            await conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_scope ON {table}(tenant_id,case_id,projection_id)")
        await conn.execute(f"""
            CREATE TABLE IF NOT EXISTS graph_view_receipts (
              receipt_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
              projection_id TEXT NOT NULL, ledger_head_hash TEXT NOT NULL, content_hash TEXT NOT NULL,
              record_json {json_type} NOT NULL, appended_at {timestamp})
        """)


async def _insert_immutable(conn: Any, *, kind: str, values: tuple[str, ...]) -> bool:
    table = _TABLES[kind]
    id_column = {"node": "node_record_id", "edge": "edge_record_id", "receipt": "receipt_id"}[kind]
    record_id, content_hash, payload = values[0], values[-2], values[-1]
    existing = await conn.fetchrow(f"SELECT content_hash,record_json FROM {table} WHERE {id_column}=$1", record_id)
    if existing:
        old = dict(existing)
        old_payload = _canonical_payload(old.get("record_json"))
        if old.get("content_hash") != content_hash or old_payload != payload:
            raise ValueError("append_only_graph_projection_conflict")
        return False
    if kind in {"node", "edge"}:
        columns = f"{id_column},tenant_id,case_id,projection_id,semantic_id,content_hash,record_json,appended_at"
    else:
        columns = f"{id_column},tenant_id,case_id,projection_id,ledger_head_hash,content_hash,record_json,appended_at"
    if _sqlite(conn):
        await conn.execute(f"INSERT INTO {table}({columns}) VALUES(?,?,?,?,?,?,?,?)", *values, time.time())
    else:
        await conn.execute(f"INSERT INTO {table}({columns}) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,NOW())", *values)
    return True


async def append_projection(
    *, nodes: list[dict[str, Any]], edges: list[dict[str, Any]], receipt: GraphProjectionReceipt
) -> dict[str, int]:
    """Validate and append one projection using bounded database round trips.

    Projection IDs and record IDs are content-addressed. Existing IDs are read in
    one query per record family and compared before a batch insert, preserving the
    append-only conflict check without an O(records) database round-trip loop.
    """

    typed_nodes, typed_edges = validate_tenant_graph(nodes, edges, tenant_id=receipt.tenant_id)
    if set(receipt.node_ids) != {node.node_id for node in typed_nodes}:
        raise ValueError("graph_receipt_node_set_mismatch")
    # Validation intentionally projects rows into TypedEdge, but persistence and
    # the receipt must retain the authoritative clock/observation metadata on
    # the original edge records.  Hashing the stripped validation projection
    # made every clock-aware production projection fail its receipt check.
    edge_ids = {canonical_hash(edge) for edge in edges}
    if set(receipt.edge_ids) != edge_ids:
        raise ValueError("graph_receipt_edge_set_mismatch")
    await ensure_schema()
    counts = {"nodes": 0, "edges": 0, "receipts": 0}
    async with await _connection() as conn:
        existing_nodes = {
            str(row["node_record_id"]): dict(row)
            for row in await conn.fetch(
                "SELECT node_record_id,content_hash,record_json FROM evidence_graph_nodes "
                "WHERE tenant_id=$1 AND case_id=$2 AND projection_id=$3",
                receipt.tenant_id, receipt.case_id, receipt.projection_id,
            )
        }
        node_values: list[tuple[Any, ...]] = []
        for raw, node in zip(nodes, typed_nodes):
            content_hash = canonical_hash(raw)
            payload = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            record_id = f"gn_{canonical_hash({'projection_id': receipt.projection_id, 'content_hash': content_hash})}"
            existing = existing_nodes.get(record_id)
            if existing:
                old_payload = _canonical_payload(existing.get("record_json"))
                if existing.get("content_hash") != content_hash or old_payload != payload:
                    raise ValueError("append_only_graph_projection_conflict")
                continue
            node_values.append((record_id, receipt.tenant_id, receipt.case_id, receipt.projection_id, node.node_id, content_hash, payload))

        existing_edges = {
            str(row["edge_record_id"]): dict(row)
            for row in await conn.fetch(
                "SELECT edge_record_id,content_hash,record_json FROM evidence_graph_edges "
                "WHERE tenant_id=$1 AND case_id=$2 AND projection_id=$3",
                receipt.tenant_id, receipt.case_id, receipt.projection_id,
            )
        }
        edge_values: list[tuple[Any, ...]] = []
        for raw, edge in zip(edges, typed_edges):
            content_hash = canonical_hash(raw)
            payload = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            record_id = f"ge_{canonical_hash({'projection_id': receipt.projection_id, 'content_hash': content_hash})}"
            semantic_id = f"{edge.source}|{edge.edge_type.value}|{edge.target}"
            existing = existing_edges.get(record_id)
            if existing:
                old_payload = _canonical_payload(existing.get("record_json"))
                if existing.get("content_hash") != content_hash or old_payload != payload:
                    raise ValueError("append_only_graph_projection_conflict")
                continue
            edge_values.append((record_id, receipt.tenant_id, receipt.case_id, receipt.projection_id, semantic_id, content_hash, payload))

        now = time.time()
        if _sqlite(conn):
            if node_values:
                await conn.executemany(
                    "INSERT INTO evidence_graph_nodes(node_record_id,tenant_id,case_id,projection_id,semantic_id,content_hash,record_json,appended_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    [(*values, now) for values in node_values],
                )
            if edge_values:
                await conn.executemany(
                    "INSERT INTO evidence_graph_edges(edge_record_id,tenant_id,case_id,projection_id,semantic_id,content_hash,record_json,appended_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    [(*values, now) for values in edge_values],
                )
        else:
            async with conn.transaction():
                if node_values:
                    await conn.executemany(
                        "INSERT INTO evidence_graph_nodes(node_record_id,tenant_id,case_id,projection_id,semantic_id,content_hash,record_json) "
                        "VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)",
                        node_values,
                    )
                if edge_values:
                    await conn.executemany(
                        "INSERT INTO evidence_graph_edges(edge_record_id,tenant_id,case_id,projection_id,semantic_id,content_hash,record_json) "
                        "VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)",
                        edge_values,
                    )
        counts["nodes"] = len(node_values)
        counts["edges"] = len(edge_values)

        receipt_dict = receipt.to_dict()
        payload = json.dumps(receipt_dict, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        counts["receipts"] += int(await _insert_immutable(conn, kind="receipt", values=(
            receipt.receipt_id, receipt.tenant_id, receipt.case_id, receipt.projection_id,
            receipt.ledger_head_hash, receipt.content_hash, payload)))
    return counts


async def load_projection(tenant_id: str, case_id: str, projection_id: str) -> dict[str, Any]:
    if not tenant_id or not case_id or not projection_id:
        raise ValueError("graph_projection_scope_required")
    await ensure_schema()
    async with await _connection() as conn:
        # SQLiteConnectionProxy translates asyncpg-style positional markers.
        query_nodes = "SELECT record_json FROM evidence_graph_nodes WHERE tenant_id=$1 AND case_id=$2 AND projection_id=$3 ORDER BY semantic_id"
        query_edges = "SELECT record_json FROM evidence_graph_edges WHERE tenant_id=$1 AND case_id=$2 AND projection_id=$3 ORDER BY semantic_id"
        node_rows = await conn.fetch(query_nodes, tenant_id, case_id, projection_id)
        edge_rows = await conn.fetch(query_edges, tenant_id, case_id, projection_id)

    def decoded(rows: Any) -> list[dict[str, Any]]:
        output = []
        for row in rows:
            value = dict(row)["record_json"]
            output.append(value if isinstance(value, dict) else json.loads(value))
        return output

    return {"projection_id": projection_id, "nodes": decoded(node_rows), "edges": decoded(edge_rows)}


__all__ = ["append_projection", "ensure_schema", "load_projection"]

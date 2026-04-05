import json
import os
import sys


def _fail(msg: str) -> None:
    print(f"[log-pull-contracts] ERROR: {msg}")
    sys.exit(1)


def _load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> None:
    path = os.getenv("LOG_PULL_CONTRACTS_PATH", os.path.join("config", "log_pull_contracts.json"))
    if not os.path.exists(path):
        _fail(f"missing contracts file: {path}")
    data = _load(path)
    if not isinstance(data, dict):
        _fail("contracts must be a JSON object")
    sources = data.get("sources")
    if not isinstance(sources, dict) or not sources:
        _fail("contracts must include a non-empty sources map")

    for key, contract in sources.items():
        if not isinstance(contract, dict):
            _fail(f"contract {key} must be an object")
        cid = contract.get("id") or key
        domain = contract.get("domain")
        if not domain:
            _fail(f"{cid}: domain is required")
        req_fields = contract.get("required_fields")
        if not isinstance(req_fields, list) or not req_fields:
            _fail(f"{cid}: required_fields must be a non-empty list")
        ttl = contract.get("ttl_seconds")
        if ttl is None or int(ttl) <= 0:
            _fail(f"{cid}: ttl_seconds must be > 0")
        acquisition = contract.get("acquisition") or {}
        method = acquisition.get("method")
        if not method:
            _fail(f"{cid}: acquisition.method is required")
        if method != "MANUAL":
            endpoint = acquisition.get("endpoint")
            if not endpoint:
                _fail(f"{cid}: acquisition.endpoint required for method {method}")
        custody_required = contract.get("custody_required")
        if custody_required not in (True, False):
            _fail(f"{cid}: custody_required must be boolean")
        chain = contract.get("chain_of_custody") or {}
        if custody_required and not chain:
            _fail(f"{cid}: chain_of_custody required when custody_required=true")

    print(f"[log-pull-contracts] OK: {len(sources)} contracts validated")


if __name__ == "__main__":
    main()

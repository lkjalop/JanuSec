from __future__ import annotations

import argparse
import csv
import json
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


def _safe(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _message_body(msg) -> str:
    if msg.is_multipart():
        parts: list[str] = []
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    payload = part.get_payload(decode=True) or b""
                    parts.append(payload.decode(errors="ignore"))
        return "\n".join(part for part in parts if part).strip()
    try:
        return _safe(msg.get_content())
    except Exception:
        payload = msg.get_payload(decode=True) or b""
        return payload.decode(errors="ignore").strip()


def build_from_eml(path: Path, out_dir: Path, tenant_id: str, recipient_hint: str | None = None) -> None:
    msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    from_addr = _safe(msg.get("From"))
    to_addr = _safe(msg.get("To") or recipient_hint)
    subject = _safe(msg.get("Subject"))
    date = _safe(msg.get("Date"))
    reply_to = _safe(msg.get("Reply-To"))
    message_id = _safe(msg.get("Message-ID")) or f"<{path.stem}@replay.local>"
    body = _message_body(msg)

    out_dir.mkdir(parents=True, exist_ok=True)
    email_message = [
        {
            "message_id": message_id,
            "timestamp": date,
            "from": from_addr,
            "to": to_addr,
            "reply_to": reply_to,
            "sender_display_name": from_addr.split("<", 1)[0].strip() if "<" in from_addr else from_addr,
            "subject": subject,
            "body": body,
            "source_file": path.name,
        }
    ]
    mailbox_trace = [
        {
            "message_id": message_id,
            "timestamp": date,
            "to": to_addr,
            "delivery_action": "delivered",
            "mailbox_folder": "Inbox",
            "transport_rule": "unknown",
        }
    ]
    manifest = {
        "tenant_id": tenant_id,
        "provider": "email",
        "files": [
            {"path": "email_message.json", "source_kind": "email_message", "labels": ["email", "exported"]},
            {"path": "mailbox_trace.json", "source_kind": "mailbox_trace", "labels": ["email", "delivery"]},
        ],
    }
    (out_dir / "email_message.json").write_text(json.dumps(email_message, indent=2), encoding="utf-8")
    (out_dir / "mailbox_trace.json").write_text(json.dumps(mailbox_trace, indent=2), encoding="utf-8")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def build_from_csv(path: Path, out_dir: Path, tenant_id: str) -> None:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            rows.append(
                {
                    "message_id": _safe(row.get("message_id")) or f"<{path.stem}-{len(rows)+1}@replay.local>",
                    "timestamp": _safe(row.get("timestamp") or row.get("ts")),
                    "from": _safe(row.get("from") or row.get("from_addr")),
                    "to": _safe(row.get("to") or row.get("recipient")),
                    "reply_to": _safe(row.get("reply_to")),
                    "sender_display_name": _safe(row.get("sender_display_name")),
                    "subject": _safe(row.get("subject")),
                    "body": _safe(row.get("body")),
                    "source_file": path.name,
                }
            )
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "tenant_id": tenant_id,
        "provider": "email",
        "files": [
            {"path": "email_message.json", "source_kind": "email_message", "labels": ["email", "exported"]},
        ],
    }
    (out_dir / "email_message.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert exported email .eml or CSV into a JanuSec replay pack.")
    ap.add_argument("input_path")
    ap.add_argument("out_dir")
    ap.add_argument("--tenant-id", default="email-export-demo")
    ap.add_argument("--recipient-hint", default="")
    args = ap.parse_args()

    src = Path(args.input_path)
    out_dir = Path(args.out_dir)
    if src.suffix.lower() == ".eml":
        build_from_eml(src, out_dir, args.tenant_id, args.recipient_hint or None)
    elif src.suffix.lower() == ".csv":
        build_from_csv(src, out_dir, args.tenant_id)
    else:
        raise SystemExit(f"unsupported input: {src.suffix}")
    print(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

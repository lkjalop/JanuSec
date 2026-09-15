"""Demo runner for MS Graph and Gmail connectors.

This script demonstrates how to use the connector skeletons and the
`TenantStore` to persist tokens. It does not perform real OAuth exchanges
without proper client credentials and registered redirect URIs.

Usage examples (fill in credentials):

    python tools/email_connector_demo.py msgraph
    python tools/email_connector_demo.py gmail

"""
from __future__ import annotations

import os
import sys
import time

from integrations.msgraph_connector import MSGraphConnector
from integrations.gmail_connector import GmailConnector
from integrations.tenant_store import TenantStore


def demo_msgraph():
    # Replace with real values for a full integration test
    client_id = os.environ.get("MSGRAPH_CLIENT_ID") or ""
    client_secret = os.environ.get("MSGRAPH_CLIENT_SECRET") or ""
    redirect = os.environ.get("MSGRAPH_REDIRECT") or "http://localhost:8080/callback"
    conn = MSGraphConnector(client_id, client_secret, redirect)
    print("Authorization URL:", conn.get_authorization_url(state="demo-state"))


def demo_gmail():
    client_id = os.environ.get("GMAIL_CLIENT_ID") or ""
    client_secret = os.environ.get("GMAIL_CLIENT_SECRET") or ""
    redirect = os.environ.get("GMAIL_REDIRECT") or "http://localhost:8080/callback"
    conn = GmailConnector(client_id, client_secret, redirect)
    print("Authorization URL:", conn.get_authorization_url(state="demo-state"))


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/email_connector_demo.py [msgraph|gmail]")
        return
    cmd = sys.argv[1].lower()
    if cmd == "msgraph":
        demo_msgraph()
    elif cmd == "gmail":
        demo_gmail()
    else:
        print("Unknown command")


if __name__ == "__main__":
    main()

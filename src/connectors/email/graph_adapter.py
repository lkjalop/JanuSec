from typing import List, Dict, Any, Optional
from src.collectors.email_o365_adapter import O365EmailCollector
from src.collectors.email_gmail_adapter import GmailEmailCollector


class GraphLikeAdapter:
    """Adapter that exposes a minimal graph_client interface backed by existing collectors.

    Methods implemented:
    - get_messages(mailbox, since)
    - get_attachments(message_id)
    """

    def __init__(self, o365_collector: O365EmailCollector = None, gmail_collector: GmailEmailCollector = None):
        self.o365 = o365_collector
        self.gmail = gmail_collector

    def get_messages(self, mailbox: str, since: Optional[float] = None) -> List[Dict[str, Any]]:
        # Prefer O365 collector when mailbox endswith domain in its config
        if self.o365:
            return self.o365.fetch_events(mailbox, since_ts=since)
        if self.gmail:
            return self.gmail.fetch_events(mailbox, since_ts=since)
        return []

    def get_attachments(self, message_id: str) -> List[Dict[str, Any]]:
        # Both collectors expose attachment retrieval; call O365 first
        if self.o365:
            return self.o365.fetch_attachments(message_id)
        if self.gmail:
            return self.gmail.fetch_attachments(message_id)
        return []

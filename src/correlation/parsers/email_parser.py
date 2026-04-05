from typing import Dict, Any
from ..canonical_event import CanonicalEvent

def parse_email_record(rec: Dict[str, Any]) -> CanonicalEvent:
    # Basic transformation; expects fields like From, Subject, Attachment-Hash
    mapped = {
        'timestamp': rec.get('timestamp'),
        'tenant': rec.get('tenant'),
        'source_type': 'email',
        'user': rec.get('From') or rec.get('Sender'),
        'subject': rec.get('Subject'),
        'raw_message_id': rec.get('Message-ID'),
        'file_hash': rec.get('Attachment-Hash'),
        'file_name': rec.get('Attachment-Name'),
        'attachment_type': rec.get('Attachment-Type'),
        'domain': rec.get('Domain'),
        'threat_tags': rec.get('threat_tags') or [],
        'mailbox': rec.get('mailbox'),
    }
    return CanonicalEvent.from_dict(mapped)

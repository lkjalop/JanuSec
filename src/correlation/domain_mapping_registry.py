"""Domain mapping registry: provides header->canonical field suggestions per domain."""
from typing import Dict, List

DOMAIN_HEADER_TEMPLATES: Dict[str, Dict[str, str]] = {
    'ai': {
        'model': 'model',
        'provider': 'model_provider',
        'model_provider': 'model_provider',
        'prompt': 'prompt',
        'tool': 'tool',
        'tool_name': 'tool',
        'tool_args': 'tool_args',
        'embedding_id': 'embedding_id',
        'vector_db': 'vector_db',
        'rag_index': 'rag_index',
        'guardrail': 'guardrail',
        'chain': 'chain',
        'agent': 'agent',
        'feature_store': 'feature_store',
        'dataset': 'dataset'
    },
    'email': {
        'From': 'user', 'Sender': 'user', 'Subject': 'subject', 'Message-ID': 'raw_message_id', 'Attachment-Hash': 'file_hash',
        'Attachment-Name': 'file_name', 'Attachment-Type': 'attachment_type'
    },
    'remote': {
        'vpn_user': 'user', 'src_ip': 'src_ip', 'dst_ip': 'dst_ip', 'auth_method': 'auth_method', 'mfa': 'mfa_result'
    },
    'iam': {
        'actor': 'user', 'action': 'action', 'policy': 'policy_id', 'prev_role': 'privilege_level_before', 'new_role': 'privilege_level_after'
    },
    'network': {
        'src_ip': 'src_ip', 'dst_ip': 'dst_ip', 'src_port': 'src_port', 'dst_port': 'dst_port', 'proto': 'protocol', 'domain': 'domain'
    },
    'endpoint': {
        'host': 'host', 'process': 'process', 'pid': 'pid', 'hash': 'file_hash', 'user': 'user'
    },
    'data': {
        'user': 'user', 'volume': 'data_volume_bytes', 'direction': 'direction', 'repository': 'repository'
    },
    'api': {
        'user': 'user', 'endpoint': 'api_endpoint', 'method': 'method', 'status': 'status'
    },
    'other': {
        'actor': 'user', 'change_type': 'config_change_type'
    }
}

def suggest_mapping(domain: str, headers: List[str]) -> Dict[str, str]:
    dm = DOMAIN_HEADER_TEMPLATES.get(domain, {})
    out: Dict[str, str] = {}
    for h in headers:
        if h in dm:
            out[h] = dm[h]
    return out

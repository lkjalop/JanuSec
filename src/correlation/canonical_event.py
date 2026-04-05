from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import time

@dataclass
class CanonicalEvent:
    timestamp: float
    tenant: Optional[str]
    source_type: str  # one of email|remote|iam|network|endpoint|data|api|ai|other
    user: Optional[str] = None
    user_role: Optional[str] = None
    host: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    domain: Optional[str] = None
    uri: Optional[str] = None
    api_endpoint: Optional[str] = None
    method: Optional[str] = None
    file_hash: Optional[str] = None
    file_name: Optional[str] = None
    attachment_type: Optional[str] = None
    auth_method: Optional[str] = None
    mfa_result: Optional[str] = None
    privilege_level_before: Optional[str] = None
    privilege_level_after: Optional[str] = None
    data_volume_bytes: Optional[int] = None
    direction: Optional[str] = None
    repository: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    outcome: Optional[str] = None
    error_code: Optional[str] = None
    threat_tags: List[str] = field(default_factory=list)
    raw_message_id: Optional[str] = None
    subject: Optional[str] = None
    mailbox: Optional[str] = None
    policy_id: Optional[str] = None
    config_change_type: Optional[str] = None
    geo_src: Optional[str] = None
    geo_dst: Optional[str] = None
    asn: Optional[str] = None
    reputation_score: Optional[float] = None
    correlation_ids: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    # AI domain (optional fields)
    model: Optional[str] = None
    model_provider: Optional[str] = None
    prompt: Optional[str] = None
    tool: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    embedding_id: Optional[str] = None
    vector_db: Optional[str] = None
    rag_index: Optional[str] = None
    guardrail: Optional[str] = None
    chain: Optional[str] = None
    agent: Optional[str] = None
    feature_store: Optional[str] = None
    dataset: Optional[str] = None

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> 'CanonicalEvent':
        ts = d.get('timestamp')
        if isinstance(ts, str):
            try:
                # naive ISO8601 parse fallback: if numeric string treat as float
                if ts.isdigit():
                    tsf = float(ts)
                else:
                    tsf = time.time()
            except Exception:
                tsf = time.time()
        elif isinstance(ts, (int, float)):
            tsf = float(ts)
        else:
            tsf = time.time()
        return CanonicalEvent(
            timestamp=tsf,
            tenant=d.get('tenant'),
            source_type=str(d.get('source_type') or d.get('domain_type') or 'other').lower(),
            user=d.get('user'), user_role=d.get('user_role'), host=d.get('host'),
            process=d.get('process'), pid=d.get('pid'), src_ip=d.get('src_ip'), dst_ip=d.get('dst_ip'),
            src_port=d.get('src_port'), dst_port=d.get('dst_port'), protocol=d.get('protocol'),
            domain=d.get('domain'), uri=d.get('uri'), api_endpoint=d.get('api_endpoint'), method=d.get('method'),
            file_hash=d.get('file_hash'), file_name=d.get('file_name'), attachment_type=d.get('attachment_type'),
            auth_method=d.get('auth_method'), mfa_result=d.get('mfa_result'),
            privilege_level_before=d.get('privilege_level_before'), privilege_level_after=d.get('privilege_level_after'),
            data_volume_bytes=d.get('data_volume_bytes'), direction=d.get('direction'), repository=d.get('repository'),
            action=d.get('action'), status=d.get('status'), outcome=d.get('outcome'), error_code=d.get('error_code'),
            threat_tags=list(d.get('threat_tags') or []), raw_message_id=d.get('raw_message_id'), subject=d.get('subject'), mailbox=d.get('mailbox'),
            policy_id=d.get('policy_id'), config_change_type=d.get('config_change_type'), geo_src=d.get('geo_src'), geo_dst=d.get('geo_dst'),
            asn=d.get('asn'), reputation_score=d.get('reputation_score'), correlation_ids=list(d.get('correlation_ids') or []), raw=d,
            model=d.get('model'), model_provider=d.get('model_provider') or d.get('provider'), prompt=d.get('prompt'),
            tool=d.get('tool') or d.get('tool_name'), tool_args=d.get('tool_args'),
            embedding_id=d.get('embedding_id'), vector_db=d.get('vector_db'), rag_index=d.get('rag_index'),
            guardrail=d.get('guardrail'), chain=d.get('chain'), agent=d.get('agent'), feature_store=d.get('feature_store'), dataset=d.get('dataset')
        )

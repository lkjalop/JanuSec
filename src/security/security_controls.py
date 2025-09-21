"""
Security Controls Implementation - Addresses all CyberStash security requirements
Author: Security Engineering Team
Version: 1.0.0

Implements secure API key management, PII redaction, role-based approvals, and audit logging.
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import re
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


@dataclass
class AuditEvent:
    """Audit event for compliance logging"""
    timestamp: str
    user_id: str
    action: str
    resource: str
    details: Dict[str, Any]
    source_ip: str
    user_agent: str
    success: bool
    risk_level: str


@dataclass
class ApprovalRequest:
    """Approval request for sensitive actions"""
    request_id: str
    action_type: str
    description: str
    requester: str
    approver_roles: List[str]
    auto_approved: bool
    approval_reason: str
    created_at: str
    expires_at: str


class SecureConfigManager:
    """
    Secure API key and configuration management
    Addresses: "Store API keys securely; never hard-code in scripts"
    """
    
    def __init__(self, vault_path: str = None):
        # Updated brand path; retain legacy env override compatibility
        self.vault_path = vault_path or os.getenv('VAULT_PATH', '/etc/janusec/vault')
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        self.logger = logging.getLogger(__name__)

        # Environment-based configuration
        self.environment = os.getenv('ENVIRONMENT', 'development')
        self.debug_mode = self.environment == 'development'
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Generate or retrieve encryption key for secrets"""
        key_file = f"{self.vault_path}/master.key"
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            key = Fernet.generate_key()
            
            # Set restrictive permissions
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Owner read/write only
            
            return key
    
    async def store_api_key(self, service_name: str, api_key: str, metadata: Dict[str, Any] = None):
        """Securely store API key with metadata"""
        
        # Encrypt the API key
        encrypted_key = self.cipher.encrypt(api_key.encode())
        
        # Create secure storage record
        record = {
            'service_name': service_name,
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'created_at': datetime.utcnow().isoformat(),
            'metadata': metadata or {},
            'key_hash': hashlib.sha256(api_key.encode()).hexdigest()[:8]  # For verification
        }
        
        # Store in secure file
        key_file = f"{self.vault_path}/{service_name}.json"
        os.makedirs(os.path.dirname(key_file), exist_ok=True)
        
        with open(key_file, 'w') as f:
            json.dump(record, f, indent=2)
        os.chmod(key_file, 0o600)
        
        self.logger.info(f"Stored API key for {service_name}")
    
    async def get_api_key(self, service_name: str) -> Optional[str]:
        """Retrieve and decrypt API key"""
        
        key_file = f"{self.vault_path}/{service_name}.json"
        
        if not os.path.exists(key_file):
            self.logger.error(f"API key not found for {service_name}")
            return None
        
        try:
            with open(key_file, 'r') as f:
                record = json.load(f)
            
            # Decrypt the API key
            encrypted_key = base64.b64decode(record['encrypted_key'])
            api_key = self.cipher.decrypt(encrypted_key).decode()
            
            return api_key
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve API key for {service_name}: {e}")
            return None
    
    async def rotate_api_key(self, service_name: str, new_api_key: str):
        """Rotate API key with backup"""
        
        # Backup old key
        old_record = None
        key_file = f"{self.vault_path}/{service_name}.json"
        
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                old_record = json.load(f)
            
            # Create backup
            backup_file = f"{self.vault_path}/{service_name}.backup.json"
            with open(backup_file, 'w') as f:
                json.dump(old_record, f, indent=2)
        
        # Store new key
        await self.store_api_key(service_name, new_api_key, {
            'rotated_at': datetime.utcnow().isoformat(),
            'previous_key_hash': old_record.get('key_hash') if old_record else None
        })
        
        self.logger.info(f"Rotated API key for {service_name}")


class PIIRedactionEngine:
    """
    PII detection and redaction before external processing
    Addresses: "Redact sensitive data before sending to external AI where required"
    """
    
    def __init__(self, metrics=None):
        self.pii_patterns = {
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'ssn_alt': re.compile(r'\b\d{9}\b'),
            'credit_card': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),
            'ip_private': re.compile(r'\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\b'),
            'windows_username': re.compile(r'\\[a-zA-Z0-9._-]+'),
            'file_paths': re.compile(r'[C-Z]:\\[^<>:"|?*\n\r]+'),
        }
        self.logger = logging.getLogger(__name__)
        self.metrics = metrics  # expected to provide async record_redaction(count)
    
    async def redact_for_external_ai(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact PII from data before sending to external AI services"""
        
        redacted_data = self._deep_copy_dict(data)
        redaction_count = 0
        
        # Fields that commonly contain PII
        sensitive_fields = [
            'command_line', 'process_args', 'file_path', 'registry_value',
            'email_content', 'email_subject', 'user_name', 'raw_payload'
        ]
        
        for field in sensitive_fields:
            if field in redacted_data and isinstance(redacted_data[field], str):
                original_value = redacted_data[field]
                redacted_value, count = self._redact_text(original_value)
                redacted_data[field] = redacted_value
                redaction_count += count
        
        # Special handling for nested raw_payload
        if 'raw_payload' in redacted_data and isinstance(redacted_data['raw_payload'], dict):
            redacted_data['raw_payload'] = await self._redact_nested_dict(redacted_data['raw_payload'])
        
        # Add redaction metadata
        redacted_data['_pii_redaction'] = {
            'redacted': redaction_count > 0,
            'redaction_count': redaction_count,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if redaction_count > 0:
            self.logger.info(f"Redacted {redaction_count} PII instances before external AI processing")
            # fire and forget metrics increment
            try:
                if self.metrics and hasattr(self.metrics, 'record_redaction'):
                    await self.metrics.record_redaction(redaction_count)
            except Exception:
                pass
        
        return redacted_data
    
    def _redact_text(self, text: str) -> tuple[str, int]:
        """Redact PII patterns from text"""
        redacted_text = text
        redaction_count = 0
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = pattern.findall(redacted_text)
            if matches:
                redacted_text = pattern.sub(f'[REDACTED_{pii_type.upper()}]', redacted_text)
                redaction_count += len(matches)
        
        return redacted_text, redaction_count
    
    async def _redact_nested_dict(self, data: dict) -> dict:
        """Recursively redact PII from nested dictionary"""
        redacted = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                redacted[key], _ = self._redact_text(value)
            elif isinstance(value, dict):
                redacted[key] = await self._redact_nested_dict(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._redact_text(item)[0] if isinstance(item, str) else item
                    for item in value
                ]
            else:
                redacted[key] = value
        
        return redacted
    
    def _deep_copy_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Deep copy dictionary to avoid modifying original"""
        import copy
        return copy.deepcopy(data)


class RoleBasedApprovalSystem:
    """
    Role-based approval system for sensitive actions
    Addresses: "Implement role-based approvals for any response actions (block/quarantine)"
    """
    
    def __init__(self):
        self.pending_approvals = {}
        self.approval_history = []
        self.role_permissions = {
            'analyst': ['view_alerts', 'investigate'],
            'senior_analyst': ['view_alerts', 'investigate', 'approve_low_risk'],
            'security_lead': ['view_alerts', 'investigate', 'approve_low_risk', 'approve_medium_risk'],
            'security_manager': ['view_alerts', 'investigate', 'approve_low_risk', 'approve_medium_risk', 'approve_high_risk'],
            'ciso': ['*']  # All permissions
        }
        
        self.action_risk_levels = {
            'isolate_endpoint': 'medium_risk',
            'block_ip': 'low_risk', 
            'quarantine_file': 'low_risk',
            'disable_user': 'high_risk',
            'reset_credentials': 'medium_risk',
            'network_block': 'medium_risk',
            'emergency_shutdown': 'high_risk'
        }
        
        self.logger = logging.getLogger(__name__)
    
    async def request_approval(self, action_type: str, description: str, requester: str, 
                             context: Dict[str, Any]) -> str:
        """Request approval for a sensitive action"""
        
        risk_level = self.action_risk_levels.get(action_type, 'medium_risk')
        required_permission = f'approve_{risk_level}'
        
        # Check if auto-approval is possible
        auto_approved = self._check_auto_approval(action_type, context)
        
        request_id = hashlib.sha256(
            f"{action_type}_{requester}_{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Determine required approver roles
        approver_roles = []
        if required_permission == 'approve_low_risk':
            approver_roles = ['senior_analyst', 'security_lead', 'security_manager', 'ciso']
        elif required_permission == 'approve_medium_risk':
            approver_roles = ['security_lead', 'security_manager', 'ciso']
        elif required_permission == 'approve_high_risk':
            approver_roles = ['security_manager', 'ciso']
        
        approval_request = ApprovalRequest(
            request_id=request_id,
            action_type=action_type,
            description=description,
            requester=requester,
            approver_roles=approver_roles,
            auto_approved=auto_approved,
            approval_reason='auto_approved' if auto_approved else 'pending',
            created_at=datetime.utcnow().isoformat(),
            expires_at=(datetime.utcnow() + timedelta(hours=24)).isoformat()
        )
        
        if not auto_approved:
            self.pending_approvals[request_id] = approval_request
            await self._notify_approvers(approval_request)
        
        self.logger.info(f"Approval requested for {action_type}: {request_id} "
                        f"(auto_approved: {auto_approved})")
        
        return request_id
    
    async def approve_action(self, request_id: str, approver: str, approver_role: str, 
                           reason: str = None) -> bool:
        """Approve a pending action"""
        
        if request_id not in self.pending_approvals:
            return False
        
        request = self.pending_approvals[request_id]
        
        # Check if approver has required role
        if approver_role not in request.approver_roles:
            self.logger.warning(f"Insufficient privileges for {approver} to approve {request_id}")
            return False
        
        # Approve the request
        request.approval_reason = reason or f"Approved by {approver}"
        self.approval_history.append(request)
        del self.pending_approvals[request_id]
        
        self.logger.info(f"Action {request.action_type} approved by {approver} ({approver_role})")
        
        return True
    
    def _check_auto_approval(self, action_type: str, context: Dict[str, Any]) -> bool:
        """Check if action can be auto-approved based on context"""
        
        # Auto-approve low-risk actions with high confidence
        if action_type in ['block_ip', 'quarantine_file']:
            confidence = context.get('confidence', 0.0)
            if confidence > 0.95:
                return True
        
        # Auto-approve during off-hours for critical threats
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:  # Outside business hours
            if context.get('severity') == 'critical':
                return True
        
        return False
    
    async def _notify_approvers(self, request: ApprovalRequest):
        """Notify eligible approvers (placeholder for integration)"""
        # This would integrate with Slack, email, or ticketing system
        self.logger.info(f"Notifying approvers for {request.action_type}: {request.approver_roles}")


class ComprehensiveAuditLogger:
    """
    Full audit logging for all actions and decisions
    Addresses: "Maintain full audit logs of prompts, responses, and actions"
    """
    
    def __init__(self, audit_file_path: str = None):
        self.audit_file_path = audit_file_path or '/var/log/janusec/audit.log'
        os.makedirs(os.path.dirname(self.audit_file_path), exist_ok=True)

        # Set up structured logging
        self.audit_logger = logging.getLogger('audit')
        handler = logging.FileHandler(self.audit_file_path)
        formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.audit_logger.addHandler(handler)
        self.audit_logger.setLevel(logging.INFO)

        # Separate file for high-sensitivity events
        self.sensitive_audit_path = '/var/log/janusec/sensitive-audit.log'
        self.sensitive_logger = logging.getLogger('sensitive_audit')
        sensitive_handler = logging.FileHandler(self.sensitive_audit_path)
        sensitive_handler.setFormatter(formatter)
        self.sensitive_logger.addHandler(sensitive_handler)
        self.sensitive_logger.setLevel(logging.INFO)
    
    async def log_event_processing(self, event_id: str, user_id: str, action: str, 
                                 result: Dict[str, Any], source_ip: str = None):
        """Log event processing decisions"""
        
        audit_event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id or 'system',
            action=f'event_processing_{action}',
            resource=f'event:{event_id}',
            details={
                'verdict': result.get('verdict'),
                'confidence': result.get('confidence'),
                'factors': result.get('factors', []),
                'processing_time_ms': result.get('processing_time_ms')
            },
            source_ip=source_ip or 'localhost',
            user_agent='janusec_platform',
            success=True,
            risk_level='low'
        )
        
        await self._write_audit_event(audit_event)
    
    async def log_ai_interaction(self, service_name: str, prompt: str, response: str, 
                               user_id: str, event_id: str = None):
        """Log AI service interactions with prompts and responses"""
        
        # Redact PII from prompt and response before logging
        redactor = PIIRedactionEngine()
        redacted_prompt = (await redactor.redact_for_external_ai({'prompt': prompt}))['prompt']
        redacted_response = (await redactor.redact_for_external_ai({'response': response}))['response']
        
        audit_event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            action='ai_interaction',
            resource=f'ai_service:{service_name}',
            details={
                'service': service_name,
                'prompt': redacted_prompt,
                'response': redacted_response,
                'event_id': event_id,
                'prompt_hash': hashlib.sha256(prompt.encode()).hexdigest()[:16],
                'response_hash': hashlib.sha256(response.encode()).hexdigest()[:16]
            },
            source_ip='localhost',
            user_agent='janusec_platform',
            success=True,
            risk_level='medium'
        )
        
        await self._write_audit_event(audit_event, sensitive=True)
    
    async def log_playbook_execution(self, playbook_id: str, event_id: str, actions: List[Dict],
                                   user_id: str, approval_id: str = None):
        """Log SOAR playbook execution with all actions"""
        
        audit_event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            action='playbook_execution',
            resource=f'playbook:{playbook_id}',
            details={
                'playbook_id': playbook_id,
                'event_id': event_id,
                'actions_count': len(actions),
                'actions': actions,
                'approval_id': approval_id
            },
            source_ip='localhost',
            user_agent='janusec_platform',
            success=all(action.get('success', False) for action in actions),
            risk_level='high'
        )
        
        await self._write_audit_event(audit_event, sensitive=True)
    
    async def log_configuration_change(self, config_type: str, old_value: Any, new_value: Any,
                                     user_id: str, source_ip: str):
        """Log configuration changes"""
        
        audit_event = AuditEvent(
            timestamp=datetime.utcnow().isoformat(),
            user_id=user_id,
            action='configuration_change',
            resource=f'config:{config_type}',
            details={
                'config_type': config_type,
                'old_value_hash': hashlib.sha256(str(old_value).encode()).hexdigest()[:16],
                'new_value_hash': hashlib.sha256(str(new_value).encode()).hexdigest()[:16],
                'change_size': abs(len(str(new_value)) - len(str(old_value)))
            },
            source_ip=source_ip,
            user_agent='janusec_platform',
            success=True,
            risk_level='medium'
        )
        
        await self._write_audit_event(audit_event, sensitive=True)
    
    async def _write_audit_event(self, audit_event: AuditEvent, sensitive: bool = False):
        """Write audit event to appropriate log file"""
        
        audit_record = asdict(audit_event)
        audit_json = json.dumps(audit_record, separators=(',', ':'))
        
        if sensitive:
            self.sensitive_logger.info(audit_json)
        else:
            self.audit_logger.info(audit_json)
    
    async def search_audit_logs(self, query: Dict[str, Any], limit: int = 100) -> List[Dict]:
        """Search audit logs (simplified implementation)"""
        # In production, this would use proper log aggregation (ELK, Splunk, etc.)
        matching_events = []
        
        # This is a simplified implementation for demonstration
        # Production would use proper indexing and search capabilities
        
        return matching_events[:limit]


# Integration class that ties everything together
class SecurityControlsManager:
    """Main security controls manager that coordinates all security components"""
    
    def __init__(self):
        self.config_manager = SecureConfigManager()
        self.pii_redactor = PIIRedactionEngine()
        self.approval_system = RoleBasedApprovalSystem()
        self.audit_logger = ComprehensiveAuditLogger()
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize security controls"""
        self.logger.info("Initializing security controls...")
        
        # Verify vault access
        test_key = await self.config_manager.get_api_key('test')
        if test_key is None:
            await self.config_manager.store_api_key('test', 'test_key_value')
        
        self.logger.info("Security controls initialized successfully")
    
    async def process_event_with_security(self, event: Dict[str, Any], user_id: str, 
                                        source_ip: str = None) -> Dict[str, Any]:
        """Process event with full security controls"""
        
        event_id = event.get('id', 'unknown')
        
        # 1. Audit event ingestion
        await self.audit_logger.log_event_processing(
            event_id, user_id, 'ingestion', 
            {'status': 'received'}, source_ip
        )
        
        # 2. Redact PII before any external processing
        redacted_event = await self.pii_redactor.redact_for_external_ai(event)
        
        # 3. Process event (this would call the main platform)
        # result = await platform.process_event(redacted_event)
        
        # 4. Log final decision
        # await self.audit_logger.log_event_processing(
        #     event_id, user_id, 'decision', result, source_ip
        # )
        
        # Return redacted event for processing
        return redacted_event


# Example usage and testing
async def demo_security_controls():
    """Demonstrate security controls functionality"""
    
    security_mgr = SecurityControlsManager()
    await security_mgr.initialize()
    
    # Demo 1: API key management
    await security_mgr.config_manager.store_api_key('eclipse_xdr', 'xdr_api_key_12345')
    api_key = await security_mgr.config_manager.get_api_key('eclipse_xdr')
    print(f"Retrieved API key: {api_key[:8]}...")
    
    # Demo 2: PII redaction
    sensitive_event = {
        'id': 'demo_001',
        'command_line': 'net user john.doe@company.com 123-45-6789',
        'file_path': 'C:\\Users\\sensitive.user\\Documents\\private.doc'
    }
    
    redacted = await security_mgr.pii_redactor.redact_for_external_ai(sensitive_event)
    print(f"Redacted command: {redacted['command_line']}")
    
    # Demo 3: Approval workflow
    request_id = await security_mgr.approval_system.request_approval(
        'isolate_endpoint', 
        'Isolate endpoint due to malware detection',
        'analyst.smith',
        {'confidence': 0.85, 'severity': 'high'}
    )
    
    print(f"Approval request ID: {request_id}")
    
    # Demo 4: Audit logging
    await security_mgr.audit_logger.log_ai_interaction(
        'threat_analyzer', 
        'Analyze this suspicious activity',
        'High probability malware detected',
        'analyst.smith',
        'demo_001'
    )
    
    print("Security controls demonstration complete!")


if __name__ == "__main__":
    import asyncio
    asyncio.run(demo_security_controls())
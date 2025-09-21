"""
SOAR Playbook Integration for Threat Sifter Platform
Automated response playbooks integrated with Eclipse XDR and AI enrichment

Author: Security Automation Team  
Version: 1.0.0
"""

import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import yaml


class PlaybookStatus(Enum):
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionType(Enum):
    ISOLATE_ENDPOINT = "isolate_endpoint"
    BLOCK_IP = "block_ip"
    QUARANTINE_FILE = "quarantine_file"
    DISABLE_USER = "disable_user"
    CREATE_TICKET = "create_ticket"
    SEND_NOTIFICATION = "send_notification"
    ENRICH_WITH_AI = "enrich_with_ai"
    UPDATE_IOC_LIST = "update_ioc_list"


@dataclass
class PlaybookAction:
    action_type: ActionType
    parameters: Dict[str, Any]
    timeout_seconds: int = 300
    retry_count: int = 3
    depends_on: List[str] = None
    approval_required: bool = False


@dataclass 
class PlaybookExecution:
    execution_id: str
    playbook_id: str
    triggered_by: str
    event_id: str
    status: PlaybookStatus
    actions: List[PlaybookAction]
    results: Dict[str, Any]
    started_at: str
    completed_at: Optional[str] = None
    error_message: Optional[str] = None


class EclipseXDRIntegration:
    """Integration with Eclipse XDR for automated response actions"""
    
    def __init__(self, api_key: str, base_url: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.session = None
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize HTTP session for XDR API calls"""
        self.session = aiohttp.ClientSession(
            headers={
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            },
            timeout=aiohttp.ClientTimeout(total=30)
        )
    
    async def isolate_endpoint(self, endpoint_id: str, reason: str) -> Dict[str, Any]:
        """Isolate an endpoint through Eclipse XDR"""
        
        payload = {
            'endpoint_id': endpoint_id,
            'action': 'isolate',
            'reason': reason,
            'requested_by': 'threat_sifter_platform'
        }
        
        try:
            async with self.session.post(
                f'{self.base_url}/endpoints/actions',
                json=payload
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.logger.info(f"Successfully isolated endpoint {endpoint_id}")
                    return {
                        'success': True,
                        'action_id': result.get('action_id'),
                        'message': 'Endpoint isolated successfully'
                    }
                else:
                    error_text = await response.text()
                    self.logger.error(f"Failed to isolate endpoint {endpoint_id}: {error_text}")
                    return {
                        'success': False,
                        'error': f"API error: {response.status} - {error_text}"
                    }
                    
        except Exception as e:
            self.logger.error(f"Exception isolating endpoint {endpoint_id}: {e}")
            return {
                'success': False,
                'error': f"Exception: {str(e)}"
            }
    
    async def block_ip_address(self, ip_address: str, duration_hours: int = 24) -> Dict[str, Any]:
        """Block an IP address through Eclipse XDR firewall"""
        
        payload = {
            'ip_address': ip_address,
            'action': 'block',
            'duration_hours': duration_hours,
            'source': 'threat_sifter_platform',
            'category': 'automated_response'
        }
        
        try:
            async with self.session.post(
                f'{self.base_url}/network/block-ip',
                json=payload
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.logger.info(f"Successfully blocked IP {ip_address}")
                    return {
                        'success': True,
                        'rule_id': result.get('rule_id'),
                        'expires_at': (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat()
                    }
                else:
                    error_text = await response.text()
                    self.logger.error(f"Failed to block IP {ip_address}: {error_text}")
                    return {
                        'success': False,
                        'error': f"API error: {response.status} - {error_text}"
                    }
                    
        except Exception as e:
            self.logger.error(f"Exception blocking IP {ip_address}: {e}")
            return {
                'success': False,
                'error': f"Exception: {str(e)}"
            }
    
    async def quarantine_file(self, file_hash: str, endpoints: List[str]) -> Dict[str, Any]:
        """Quarantine a file across specified endpoints"""
        
        payload = {
            'file_hash': file_hash,
            'endpoints': endpoints,
            'action': 'quarantine',
            'source': 'threat_sifter_platform'
        }
        
        try:
            async with self.session.post(
                f'{self.base_url}/files/quarantine',
                json=payload
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.logger.info(f"Successfully quarantined file {file_hash}")
                    return {
                        'success': True,
                        'quarantine_id': result.get('quarantine_id'),
                        'affected_endpoints': result.get('affected_endpoints', [])
                    }
                else:
                    error_text = await response.text()
                    self.logger.error(f"Failed to quarantine file {file_hash}: {error_text}")
                    return {
                        'success': False,
                        'error': f"API error: {response.status} - {error_text}"
                    }
                    
        except Exception as e:
            self.logger.error(f"Exception quarantining file {file_hash}: {e}")
            return {
                'success': False,
                'error': f"Exception: {str(e)}"
            }
    
    async def disable_user_account(self, username: str, domain: str = None) -> Dict[str, Any]:
        """Disable a user account through Eclipse XDR"""
        
        payload = {
            'username': username,
            'domain': domain,
            'action': 'disable',
            'reason': 'Automated response to security incident',
            'source': 'threat_sifter_platform'
        }
        
        try:
            async with self.session.post(
                f'{self.base_url}/users/disable',
                json=payload
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    self.logger.info(f"Successfully disabled user {username}")
                    return {
                        'success': True,
                        'user_id': result.get('user_id'),
                        'disabled_at': result.get('disabled_at')
                    }
                else:
                    error_text = await response.text()
                    self.logger.error(f"Failed to disable user {username}: {error_text}")
                    return {
                        'success': False,
                        'error': f"API error: {response.status} - {error_text}"
                    }
                    
        except Exception as e:
            self.logger.error(f"Exception disabling user {username}: {e}")
            return {
                'success': False,
                'error': f"Exception: {str(e)}"
            }


class AIEnrichmentService:
    """AI-powered threat intelligence enrichment"""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.session = None
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self):
        """Initialize AI enrichment service"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60)
        )
    
    async def enrich_threat_context(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich threat context using AI analysis"""
        
        # Prepare prompt for AI analysis
        prompt = self._build_enrichment_prompt(event_data)
        
        try:
            # In production, this would call your preferred AI service
            # For now, we'll simulate AI analysis
            
            enrichment = await self._simulate_ai_analysis(event_data)
            
            self.logger.info(f"AI enrichment completed for event {event_data.get('id')}")
            
            return {
                'success': True,
                'enrichment': enrichment,
                'confidence': enrichment.get('confidence', 0.0),
                'analysis_time_ms': 1500
            }
            
        except Exception as e:
            self.logger.error(f"AI enrichment failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'enrichment': {}
            }
    
    def _build_enrichment_prompt(self, event_data: Dict[str, Any]) -> str:
        """Build AI prompt for threat analysis"""
        
        return f"""
        Analyze this security event for threat intelligence:
        
        Event Type: {event_data.get('event_type', 'unknown')}
        Severity: {event_data.get('severity', 'unknown')}
        Source: {event_data.get('source', 'unknown')}
        
        Details: {json.dumps(event_data.get('details', {}), indent=2)}
        
        Please provide:
        1. MITRE ATT&CK technique mapping
        2. Threat actor attribution if possible
        3. IOCs (Indicators of Compromise) extracted
        4. Recommended response actions
        5. Confidence level (0.0 - 1.0)
        """
    
    async def _simulate_ai_analysis(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate AI analysis (replace with actual AI service call)"""
        
        # Simulate processing time
        await asyncio.sleep(1.5)
        
        event_type = event_data.get('event_type', 'unknown')
        details = event_data.get('details', {})
        
        # Basic rule-based enrichment simulation
        enrichment = {
            'mitre_tactics': [],
            'mitre_techniques': [],
            'threat_actors': [],
            'iocs': [],
            'recommended_actions': [],
            'confidence': 0.0
        }
        
        if event_type == 'malware_detected':
            enrichment.update({
                'mitre_tactics': ['Execution', 'Defense Evasion'],
                'mitre_techniques': ['T1055', 'T1027'],
                'threat_actors': ['APT29', 'Lazarus Group'],
                'iocs': [details.get('file_hash', ''), details.get('c2_domain', '')],
                'recommended_actions': ['quarantine_file', 'isolate_endpoint'],
                'confidence': 0.85
            })
        
        elif event_type == 'lateral_movement':
            enrichment.update({
                'mitre_tactics': ['Lateral Movement', 'Credential Access'],
                'mitre_techniques': ['T1021', 'T1003'],
                'recommended_actions': ['disable_user', 'block_ip'],
                'confidence': 0.75
            })
        
        elif event_type == 'data_exfiltration':
            enrichment.update({
                'mitre_tactics': ['Exfiltration'],
                'mitre_techniques': ['T1041'],
                'recommended_actions': ['block_ip', 'create_ticket'],
                'confidence': 0.90
            })
        
        return enrichment


class NotificationService:
    """Send notifications through various channels"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    async def send_slack_notification(self, channel: str, message: str, 
                                    severity: str = 'medium') -> Dict[str, Any]:
        """Send notification to Slack channel"""
        
        # Color coding based on severity
        color_map = {
            'low': '#36a64f',      # Green
            'medium': '#ff9500',   # Orange  
            'high': '#ff0000',     # Red
            'critical': '#8b0000'  # Dark Red
        }
        
        slack_payload = {
            'channel': channel,
            'attachments': [{
                'color': color_map.get(severity, '#36a64f'),
                'title': f'🚨 Security Alert - {severity.upper()}',
                'text': message,
                'footer': 'Threat Sifter Platform',
                'ts': int(datetime.utcnow().timestamp())
            }]
        }
        
        try:
            webhook_url = self.config.get('slack_webhook_url')
            if not webhook_url:
                return {'success': False, 'error': 'Slack webhook URL not configured'}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(webhook_url, json=slack_payload) as response:
                    if response.status == 200:
                        self.logger.info(f"Slack notification sent to {channel}")
                        return {'success': True, 'message': 'Notification sent successfully'}
                    else:
                        error_text = await response.text()
                        self.logger.error(f"Failed to send Slack notification: {error_text}")
                        return {'success': False, 'error': f"HTTP {response.status}: {error_text}"}
                        
        except Exception as e:
            self.logger.error(f"Exception sending Slack notification: {e}")
            return {'success': False, 'error': str(e)}
    
    async def send_email_notification(self, recipients: List[str], subject: str, 
                                    body: str) -> Dict[str, Any]:
        """Send email notification (placeholder for SMTP integration)"""
        
        # In production, integrate with SMTP server or email service
        self.logger.info(f"Email notification sent to {recipients}: {subject}")
        
        return {
            'success': True,
            'recipients': recipients,
            'subject': subject,
            'sent_at': datetime.utcnow().isoformat()
        }


class TicketingIntegration:
    """Integration with ticketing systems (ServiceNow, Jira, etc.)"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.system_type = config.get('system_type', 'servicenow')
        self.logger = logging.getLogger(__name__)
    
    async def create_security_ticket(self, title: str, description: str, 
                                   severity: str, assignee: str = None) -> Dict[str, Any]:
        """Create a security incident ticket"""
        
        ticket_data = {
            'short_description': title,
            'description': description,
            'category': 'Security',
            'subcategory': 'Security Incident',
            'priority': self._map_severity_to_priority(severity),
            'assigned_to': assignee,
            'caller_id': 'threat_sifter_platform',
            'created_by': 'threat_sifter_platform'
        }
        
        try:
            if self.system_type == 'servicenow':
                return await self._create_servicenow_ticket(ticket_data)
            elif self.system_type == 'jira':
                return await self._create_jira_ticket(ticket_data)
            else:
                return await self._simulate_ticket_creation(ticket_data)
                
        except Exception as e:
            self.logger.error(f"Failed to create ticket: {e}")
            return {'success': False, 'error': str(e)}
    
    async def _create_servicenow_ticket(self, ticket_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create ticket in ServiceNow"""
        
        servicenow_config = self.config.get('servicenow', {})
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{servicenow_config.get('instance_url')}/api/now/table/incident",
                json=ticket_data,
                auth=aiohttp.BasicAuth(
                    servicenow_config.get('username'),
                    servicenow_config.get('password')
                ),
                headers={'Content-Type': 'application/json'}
            ) as response:
                if response.status == 201:
                    result = await response.json()
                    ticket_number = result['result']['number']
                    
                    self.logger.info(f"ServiceNow ticket created: {ticket_number}")
                    return {
                        'success': True,
                        'ticket_number': ticket_number,
                        'ticket_id': result['result']['sys_id']
                    }
                else:
                    error_text = await response.text()
                    return {'success': False, 'error': f"HTTP {response.status}: {error_text}"}
    
    async def _simulate_ticket_creation(self, ticket_data: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate ticket creation for demo purposes"""
        
        import uuid
        ticket_number = f"INC{str(uuid.uuid4())[:8].upper()}"
        
        self.logger.info(f"Simulated ticket created: {ticket_number}")
        return {
            'success': True,
            'ticket_number': ticket_number,
            'ticket_id': str(uuid.uuid4())
        }
    
    def _map_severity_to_priority(self, severity: str) -> str:
        """Map threat severity to ticket priority"""
        severity_map = {
            'critical': '1 - Critical',
            'high': '2 - High', 
            'medium': '3 - Moderate',
            'low': '4 - Low'
        }
        return severity_map.get(severity, '3 - Moderate')


class SOARPlaybookEngine:
    """Main SOAR playbook execution engine"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.xdr_integration = EclipseXDRIntegration(
            config['eclipse_xdr']['api_key'],
            config['eclipse_xdr']['base_url']
        )
        self.ai_enrichment = AIEnrichmentService(
            config.get('ai_service', {}).get('api_key')
        )
        self.notification_service = NotificationService(
            config.get('notifications', {})
        )
        self.ticketing = TicketingIntegration(
            config.get('ticketing', {})
        )
        
        self.active_executions = {}
        self.playbook_definitions = {}
        self.logger = logging.getLogger(__name__)
        
        # Load playbook definitions
        self._load_playbook_definitions()
    
    async def initialize(self):
        """Initialize all SOAR components"""
        await self.xdr_integration.initialize()
        await self.ai_enrichment.initialize()
        self.logger.info("SOAR playbook engine initialized")
    
    def _load_playbook_definitions(self):
        """Load playbook definitions from configuration"""
        
        self.playbook_definitions = {
            'malware_response': {
                'name': 'Malware Detection Response',
                'trigger_conditions': {
                    'event_type': 'malware_detected',
                    'confidence_threshold': 0.8
                },
                'actions': [
                    {
                        'action_type': 'enrich_with_ai',
                        'parameters': {},
                        'timeout_seconds': 60
                    },
                    {
                        'action_type': 'quarantine_file',
                        'parameters': {
                            'file_hash': '${event.details.file_hash}',
                            'endpoints': ['${event.details.endpoint}']
                        },
                        'depends_on': ['enrich_with_ai'],
                        'approval_required': False
                    },
                    {
                        'action_type': 'isolate_endpoint',
                        'parameters': {
                            'endpoint_id': '${event.details.endpoint}',
                            'reason': 'Malware detected - automated response'
                        },
                        'depends_on': ['quarantine_file'],
                        'approval_required': True
                    },
                    {
                        'action_type': 'create_ticket',
                        'parameters': {
                            'title': 'Malware Detected: ${event.details.file_name}',
                            'description': 'Automated malware response executed. File quarantined and endpoint isolated.',
                            'severity': '${event.severity}'
                        },
                        'depends_on': ['quarantine_file']
                    },
                    {
                        'action_type': 'send_notification',
                        'parameters': {
                            'channel': '#security-alerts',
                            'message': '🦠 Malware detected and contained: ${event.details.file_name}',
                            'severity': '${event.severity}'
                        },
                        'depends_on': ['quarantine_file']
                    }
                ]
            },
            
            'lateral_movement_response': {
                'name': 'Lateral Movement Response',
                'trigger_conditions': {
                    'event_type': 'lateral_movement',
                    'confidence_threshold': 0.7
                },
                'actions': [
                    {
                        'action_type': 'enrich_with_ai',
                        'parameters': {},
                        'timeout_seconds': 60
                    },
                    {
                        'action_type': 'disable_user',
                        'parameters': {
                            'username': '${event.details.username}',
                            'domain': '${event.details.domain}'
                        },
                        'depends_on': ['enrich_with_ai'],
                        'approval_required': True
                    },
                    {
                        'action_type': 'block_ip',
                        'parameters': {
                            'ip_address': '${event.details.source_ip}',
                            'duration_hours': 24
                        },
                        'approval_required': False
                    },
                    {
                        'action_type': 'create_ticket',
                        'parameters': {
                            'title': 'Lateral Movement Detected: ${event.details.username}',
                            'description': 'Suspected lateral movement activity detected. User disabled and source IP blocked.',
                            'severity': '${event.severity}',
                            'assignee': 'security-team'
                        }
                    }
                ]
            },
            
            'data_exfiltration_response': {
                'name': 'Data Exfiltration Response',
                'trigger_conditions': {
                    'event_type': 'data_exfiltration',
                    'confidence_threshold': 0.9
                },
                'actions': [
                    {
                        'action_type': 'block_ip',
                        'parameters': {
                            'ip_address': '${event.details.destination_ip}',
                            'duration_hours': 168  # 1 week
                        },
                        'approval_required': False
                    },
                    {
                        'action_type': 'isolate_endpoint',
                        'parameters': {
                            'endpoint_id': '${event.details.endpoint}',
                            'reason': 'Data exfiltration detected - emergency isolation'
                        },
                        'approval_required': False  # Emergency response
                    },
                    {
                        'action_type': 'create_ticket',
                        'parameters': {
                            'title': 'CRITICAL: Data Exfiltration Detected',
                            'description': 'Potential data exfiltration detected. Endpoint isolated and destination IP blocked.',
                            'severity': 'critical',
                            'assignee': 'incident-response-team'
                        }
                    },
                    {
                        'action_type': 'send_notification',
                        'parameters': {
                            'channel': '#security-critical',
                            'message': '🚨 CRITICAL: Data exfiltration detected and contained. Immediate investigation required.',
                            'severity': 'critical'
                        }
                    }
                ]
            }
        }
    
    async def execute_playbook(self, playbook_id: str, event_data: Dict[str, Any], 
                             triggered_by: str = 'system') -> str:
        """Execute a SOAR playbook"""
        
        if playbook_id not in self.playbook_definitions:
            raise ValueError(f"Playbook {playbook_id} not found")
        
        import uuid
        execution_id = str(uuid.uuid4())
        
        playbook_def = self.playbook_definitions[playbook_id]
        
        # Create playbook execution record
        execution = PlaybookExecution(
            execution_id=execution_id,
            playbook_id=playbook_id,
            triggered_by=triggered_by,
            event_id=event_data.get('id', 'unknown'),
            status=PlaybookStatus.PENDING,
            actions=[],
            results={},
            started_at=datetime.utcnow().isoformat()
        )
        
        # Convert action definitions to PlaybookAction objects
        for action_def in playbook_def['actions']:
            action = PlaybookAction(
                action_type=ActionType(action_def['action_type']),
                parameters=action_def['parameters'],
                timeout_seconds=action_def.get('timeout_seconds', 300),
                retry_count=action_def.get('retry_count', 3),
                depends_on=action_def.get('depends_on', []),
                approval_required=action_def.get('approval_required', False)
            )
            execution.actions.append(action)
        
        self.active_executions[execution_id] = execution
        
        # Start execution asynchronously
        asyncio.create_task(self._execute_playbook_async(execution, event_data))
        
        self.logger.info(f"Started playbook execution {execution_id} for {playbook_id}")
        
        return execution_id
    
    async def _execute_playbook_async(self, execution: PlaybookExecution, 
                                    event_data: Dict[str, Any]):
        """Execute playbook actions asynchronously"""
        
        execution.status = PlaybookStatus.RUNNING
        completed_actions = set()
        
        try:
            while len(completed_actions) < len(execution.actions):
                # Find actions ready to execute
                ready_actions = []
                
                for i, action in enumerate(execution.actions):
                    action_id = f"action_{i}"
                    
                    if action_id in completed_actions:
                        continue
                    
                    # Check dependencies
                    if action.depends_on:
                        dependencies_met = all(
                            f"action_{j}" in completed_actions
                            for j, dep_action in enumerate(execution.actions)
                            if dep_action.action_type.value in action.depends_on
                        )
                        if not dependencies_met:
                            continue
                    
                    ready_actions.append((i, action, action_id))
                
                if not ready_actions:
                    break  # No more actions can be executed
                
                # Execute ready actions
                for action_index, action, action_id in ready_actions:
                    try:
                        result = await self._execute_single_action(action, event_data, execution.results)
                        execution.results[action_id] = result
                        completed_actions.add(action_id)
                        
                        self.logger.info(f"Completed action {action_id}: {action.action_type.value}")
                        
                    except Exception as e:
                        self.logger.error(f"Action {action_id} failed: {e}")
                        execution.results[action_id] = {
                            'success': False,
                            'error': str(e)
                        }
                        completed_actions.add(action_id)  # Mark as completed even if failed
                
                # Brief pause between action batches
                await asyncio.sleep(1)
            
            execution.status = PlaybookStatus.COMPLETED
            execution.completed_at = datetime.utcnow().isoformat()
            
            self.logger.info(f"Playbook execution {execution.execution_id} completed successfully")
            
        except Exception as e:
            execution.status = PlaybookStatus.FAILED
            execution.error_message = str(e)
            execution.completed_at = datetime.utcnow().isoformat()
            
            self.logger.error(f"Playbook execution {execution.execution_id} failed: {e}")
    
    async def _execute_single_action(self, action: PlaybookAction, event_data: Dict[str, Any], 
                                   previous_results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single playbook action"""
        
        # Substitute variables in parameters
        resolved_params = self._resolve_parameters(action.parameters, event_data, previous_results)
        
        if action.action_type == ActionType.ISOLATE_ENDPOINT:
            return await self.xdr_integration.isolate_endpoint(
                resolved_params['endpoint_id'],
                resolved_params['reason']
            )
        
        elif action.action_type == ActionType.BLOCK_IP:
            return await self.xdr_integration.block_ip_address(
                resolved_params['ip_address'],
                resolved_params.get('duration_hours', 24)
            )
        
        elif action.action_type == ActionType.QUARANTINE_FILE:
            return await self.xdr_integration.quarantine_file(
                resolved_params['file_hash'],
                resolved_params['endpoints']
            )
        
        elif action.action_type == ActionType.DISABLE_USER:
            return await self.xdr_integration.disable_user_account(
                resolved_params['username'],
                resolved_params.get('domain')
            )
        
        elif action.action_type == ActionType.ENRICH_WITH_AI:
            return await self.ai_enrichment.enrich_threat_context(event_data)
        
        elif action.action_type == ActionType.SEND_NOTIFICATION:
            return await self.notification_service.send_slack_notification(
                resolved_params['channel'],
                resolved_params['message'],
                resolved_params.get('severity', 'medium')
            )
        
        elif action.action_type == ActionType.CREATE_TICKET:
            return await self.ticketing.create_security_ticket(
                resolved_params['title'],
                resolved_params['description'],
                resolved_params['severity'],
                resolved_params.get('assignee')
            )
        
        else:
            return {'success': False, 'error': f'Unknown action type: {action.action_type}'}
    
    def _resolve_parameters(self, parameters: Dict[str, Any], event_data: Dict[str, Any], 
                          previous_results: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve variable placeholders in action parameters"""
        
        resolved = {}
        
        for key, value in parameters.items():
            if isinstance(value, str) and '${' in value:
                # Simple variable substitution
                resolved_value = value
                
                # Replace event variables
                if '${event.' in resolved_value:
                    import re
                    event_vars = re.findall(r'\$\{event\.([^}]+)\}', resolved_value)
                    for var_path in event_vars:
                        var_value = self._get_nested_value(event_data, var_path.split('.'))
                        resolved_value = resolved_value.replace(f'${{event.{var_path}}}', str(var_value))
                
                # Replace result variables
                if '${result.' in resolved_value:
                    import re
                    result_vars = re.findall(r'\$\{result\.([^}]+)\}', resolved_value)
                    for var_path in result_vars:
                        var_value = self._get_nested_value(previous_results, var_path.split('.'))
                        resolved_value = resolved_value.replace(f'${{result.{var_path}}}', str(var_value))
                
                resolved[key] = resolved_value
            else:
                resolved[key] = value
        
        return resolved
    
    def _get_nested_value(self, data: Dict[str, Any], path: List[str]) -> Any:
        """Get nested value from dictionary using path"""
        
        current = data
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a playbook execution"""
        
        if execution_id not in self.active_executions:
            return None
        
        execution = self.active_executions[execution_id]
        return {
            'execution_id': execution_id,
            'playbook_id': execution.playbook_id,
            'status': execution.status.value,
            'started_at': execution.started_at,
            'completed_at': execution.completed_at,
            'results': execution.results,
            'error_message': execution.error_message
        }


# Example usage and configuration
SOAR_CONFIG = {
    'eclipse_xdr': {
        'api_key': 'your_eclipse_xdr_api_key',
        'base_url': 'https://api.eclipsexdr.com/v1'
    },
    'ai_service': {
        'api_key': 'your_ai_service_api_key'
    },
    'notifications': {
        'slack_webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
    },
    'ticketing': {
        'system_type': 'servicenow',
        'servicenow': {
            'instance_url': 'https://your-instance.service-now.com',
            'username': 'your_username',
            'password': 'your_password'
        }
    }
}


async def demo_soar_playbook():
    """Demonstrate SOAR playbook execution"""
    
    # Initialize SOAR engine
    soar_engine = SOARPlaybookEngine(SOAR_CONFIG)
    await soar_engine.initialize()
    
    # Sample malware detection event
    malware_event = {
        'id': 'evt_001',
        'event_type': 'malware_detected',
        'severity': 'high',
        'confidence': 0.95,
        'timestamp': datetime.utcnow().isoformat(),
        'details': {
            'file_hash': 'a1b2c3d4e5f6789...',
            'file_name': 'suspicious.exe',
            'endpoint': 'workstation-001',
            'user': 'john.doe'
        }
    }
    
    # Execute malware response playbook
    execution_id = await soar_engine.execute_playbook(
        'malware_response',
        malware_event,
        'threat_sifter_platform'
    )
    
    print(f"Started playbook execution: {execution_id}")
    
    # Monitor execution status
    while True:
        status = soar_engine.get_execution_status(execution_id)
        print(f"Status: {status['status']}")
        
        if status['status'] in ['completed', 'failed']:
            print(f"Final results: {json.dumps(status['results'], indent=2)}")
            break
        
        await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(demo_soar_playbook())
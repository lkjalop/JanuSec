# Network Infrastructure Security: iBGP, OSPF, IPsec, VXLAN, MACsec
## Detection, Prevention & Threat Intelligence

**Status:** RFC (Request for Comments)
**Author:** Platform Architecture Team
**Date:** 2025-11-30
**Target Release:** Q1-Q2 2025

---

## Executive Summary

**Market Gap:** Traditional security platforms (EDR, SIEM, XDR) focus on endpoints/cloud but **ignore network infrastructure**. BGP hijacking, OSPF poisoning, VXLAN misconfigurations, and IPsec attacks cause massive outages and data breaches, yet have **no visibility in most SOCs**.

**Opportunity:** JanuSec can become the **first AI-driven platform** to correlate network infrastructure threats with endpoint/cloud attacks, providing true "data center to edge" visibility.

**Value Proposition:**
- Detect BGP route hijacking before traffic is diverted
- Identify OSPF LSA poisoning and routing loops
- Monitor IPsec tunnel failures and downgrade attacks
- Validate VXLAN segment isolation and VTEP integrity
- Ensure MACsec encryption enforcement

**Competitive Advantage:** No major vendor does this well:
- **CrowdStrike/SentinelOne:** Endpoint-only, no network infrastructure
- **Splunk/Rapid7:** Log aggregation, no protocol-aware detection
- **Darktrace/Vectra:** Network behavior, but not infrastructure-focused
- **Cisco/Palo Alto:** Network-centric, but weak on cross-domain correlation

**JanuSec positioning:** "The only platform that correlates network infrastructure attacks with endpoint/cloud/identity for complete kill chain reconstruction."

---

## Table of Contents

1. [Threat Landscape](#threat-landscape)
2. [Multi-Cloud Network Security](#multi-cloud-network-security)
3. [Cloud-Agnostic Connector Architecture](#cloud-agnostic-connector-architecture)
4. [iBGP Security](#ibgp-security)
5. [OSPF Security](#ospf-security)
6. [IPsec Security](#ipsec-security)
7. [VXLAN Security](#vxlan-security)
8. [MACsec Security](#macsec-security)
9. [Data Ingestion Pipeline](#data-ingestion-pipeline)
10. [HopGraph Integration](#hopgraph-integration)
11. [Tier 1/Tier 2 LLM Enrichment](#tier-1tier-2-llm-enrichment)
12. [SOC Analyst Tooling](#soc-analyst-tooling)
13. [Threat Hunter Capabilities](#threat-hunter-capabilities)
14. [Forensic Analysis Tools](#forensic-analysis-tools)
15. [CCIE-Level Network Analysis](#ccie-level-network-analysis)
16. [Detection Architecture](#detection-architecture)
17. [UI/UX for NetOps Teams](#uiux-for-netops-teams)
18. [Persona-Based Reporting](#persona-based-reporting)
19. [Competitive Analysis](#competitive-analysis)
20. [Implementation Roadmap](#implementation-roadmap)

---

## Threat Landscape

### Why Network Infrastructure Security Matters

**Real-World Incidents:**
- **2008 YouTube BGP Hijack:** Pakistan Telecom hijacked YouTube's prefix, caused global outage
- **2018 Amazon Route 53 BGP Hijack:** Attackers stole $152,000 in cryptocurrency by hijacking AWS routes
- **2020 Cloudflare BGP Leak:** Misconfiguration leaked 1,000+ routes
- **2022 VXLAN Escape:** Researchers showed VM escape via VXLAN encapsulation bugs

**Attack Vectors:**
```
Network Infrastructure Attack Kill Chain:

1. Reconnaissance
   ↓ Attacker maps network topology via traceroute/BGP looking glasses

2. Initial Access
   ↓ Compromise router with weak SNMP community string

3. Lateral Movement
   ↓ Use compromised router to inject OSPF LSAs

4. Traffic Manipulation
   ↓ Inject false BGP routes to redirect traffic through attacker-controlled AS

5. Data Exfiltration / Manipulation
   ↓ Man-in-the-middle on redirected traffic, capture credentials

6. Persistence
   ↓ Maintain malicious routes, evade detection
```

**Current Detection Gap:**
- **EDR:** Can't see network protocols (operates at host level)
- **SIEM:** Receives router logs, but no protocol analysis
- **IDS/IPS:** Signature-based, misses novel attacks
- **Network monitoring:** Focuses on performance, not security

**JanuSec Advantage:**
- Protocol-aware detection
- Cross-domain correlation (network + endpoint + cloud)
- AI-driven anomaly detection for routing behavior
- HopGraph visualization of attack paths through network infrastructure

---

## Multi-Cloud Network Security

### 2.1 Cloud-Agnostic Architecture

**Design Philosophy:** JanuSec network monitoring works across **ANY** cloud provider or private cloud by abstracting network telemetry into a unified data model.

**Supported Environments:**

| Cloud Provider | Network Services | Data Sources | Integration Method |
|----------------|------------------|--------------|-------------------|
| **AWS** | VPC Flow Logs, Transit Gateway, Direct Connect, AWS PrivateLink | CloudWatch Logs, EventBridge, VPC Flow Logs (S3/CloudWatch) | AWS SDK + CloudWatch Logs API |
| **Azure** | Virtual Network, ExpressRoute, VPN Gateway, Azure Firewall | Network Watcher Flow Logs, Azure Monitor, Event Hubs | Azure SDK + Event Hubs |
| **GCP** | VPC, Cloud Interconnect, Cloud VPN, Cloud NAT | VPC Flow Logs (Cloud Logging), Pub/Sub | GCP SDK + Pub/Sub |
| **Oracle Cloud** | VCN, FastConnect, DRG, NAT Gateway | VCN Flow Logs, Logging Analytics | Oracle Cloud SDK |
| **VMware (vSphere/NSX)** | NSX-T, vDS, vSphere Network | NSX-T API, syslog, vRealize Log Insight | REST API + syslog |
| **OpenStack** | Neutron, OVN, Kuryr | Neutron logs, OVN southbound DB | OpenStack API |
| **HP Cloud / HPE GreenLake** | Virtual Networks, HPE Aruba | Syslog, SNMP traps | Syslog + SNMP |
| **Private Data Center** | Cisco ACI, Arista CloudVision, Juniper Contrail | Syslog, NETCONF, gNMI, SNMP | Multi-vendor connectors |

### 2.2 Unified Network Telemetry Model

**Abstraction Layer:** Normalize cloud-specific formats into JanuSec canonical schema.

```python
"""
cloud_network_normalizer.py - Normalize multi-cloud network data
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any
from datetime import datetime


@dataclass
class UnifiedNetworkFlow:
    """Cloud-agnostic network flow record"""

    # Universal fields
    timestamp: datetime
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str  # TCP, UDP, ICMP, etc.
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    action: str  # ACCEPT, REJECT, DROP

    # Cloud context
    cloud_provider: str  # aws, azure, gcp, oracle, vmware, openstack, private
    region: str
    vpc_id: Optional[str]
    subnet_id: Optional[str]

    # Source/dest metadata
    source_instance_id: Optional[str]
    source_resource_type: Optional[str]  # vm, container, lambda, etc.
    dest_instance_id: Optional[str]
    dest_resource_type: Optional[str]

    # Network path
    gateway_id: Optional[str]  # Transit Gateway, ExpressRoute, etc.
    nat_gateway_id: Optional[str]
    firewall_rule_id: Optional[str]

    # Enrichment
    source_tags: Dict[str, str]
    dest_tags: Dict[str, str]
    geo_source: Optional[Dict]
    geo_dest: Optional[Dict]

    # Original raw data (for forensics)
    raw_event: Dict[str, Any]


class CloudNetworkNormalizer:
    """Normalize cloud-specific network logs to unified format"""

    def normalize_aws_vpc_flow(self, flow_log: Dict) -> UnifiedNetworkFlow:
        """
        Normalize AWS VPC Flow Log

        AWS Format (v5):
        account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes
        start end action log-status vpc-id subnet-id instance-id tcp-flags type pkt-srcaddr
        pkt-dstaddr region az-id sublocation-type sublocation-id pkt-src-aws-service
        pkt-dst-aws-service flow-direction traffic-path
        """
        return UnifiedNetworkFlow(
            timestamp=datetime.fromtimestamp(flow_log['start']),
            source_ip=flow_log['srcaddr'],
            source_port=int(flow_log['srcport']),
            dest_ip=flow_log['dstaddr'],
            dest_port=int(flow_log['dstport']),
            protocol=self._protocol_number_to_name(flow_log['protocol']),
            bytes_sent=int(flow_log['bytes']),
            bytes_received=0,  # AWS flow logs don't split by direction
            packets_sent=int(flow_log['packets']),
            packets_received=0,
            action=flow_log['action'],  # ACCEPT or REJECT

            cloud_provider='aws',
            region=flow_log.get('region'),
            vpc_id=flow_log.get('vpc-id'),
            subnet_id=flow_log.get('subnet-id'),

            source_instance_id=flow_log.get('instance-id') if flow_log.get('flow-direction') == 'egress' else None,
            dest_instance_id=flow_log.get('instance-id') if flow_log.get('flow-direction') == 'ingress' else None,
            source_resource_type='ec2',
            dest_resource_type=None,

            gateway_id=None,  # Would need enrichment from CloudTrail
            nat_gateway_id=None,
            firewall_rule_id=None,

            source_tags={},
            dest_tags={},
            geo_source=None,
            geo_dest=None,

            raw_event=flow_log
        )

    def normalize_azure_nsg_flow(self, flow_log: Dict) -> UnifiedNetworkFlow:
        """
        Normalize Azure NSG Flow Log

        Azure Format:
        {
          "time": "...",
          "systemId": "...",
          "macAddress": "...",
          "category": "NetworkSecurityGroupFlowEvent",
          "resourceId": "/subscriptions/.../networkSecurityGroups/...",
          "operationName": "NetworkSecurityGroupFlowEvents",
          "properties": {
            "flows": [{
              "rule": "DefaultRule_AllowInternetOutBound",
              "flows": [{
                "mac": "...",
                "flowTuples": ["1638360000,10.0.0.4,13.107.21.200,52804,443,T,O,A,B,,,"]
              }]
            }]
          }
        }
        """
        # Parse flowTuple: timestamp,srcIP,destIP,srcPort,destPort,protocol,direction,decision,flowState,packets,bytes
        props = flow_log['properties']['flows'][0]['flows'][0]
        tuple_parts = props['flowTuples'][0].split(',')

        return UnifiedNetworkFlow(
            timestamp=datetime.fromtimestamp(int(tuple_parts[0])),
            source_ip=tuple_parts[1],
            source_port=int(tuple_parts[3]),
            dest_ip=tuple_parts[2],
            dest_port=int(tuple_parts[4]),
            protocol=tuple_parts[5],  # T=TCP, U=UDP
            bytes_sent=int(tuple_parts[10]) if len(tuple_parts) > 10 else 0,
            bytes_received=0,
            packets_sent=int(tuple_parts[9]) if len(tuple_parts) > 9 else 0,
            packets_received=0,
            action='ACCEPT' if tuple_parts[7] == 'A' else 'REJECT',

            cloud_provider='azure',
            region=self._extract_azure_region(flow_log['resourceId']),
            vpc_id=self._extract_azure_vnet(flow_log['resourceId']),
            subnet_id=None,

            source_instance_id=None,
            source_resource_type=None,
            dest_instance_id=None,
            dest_resource_type=None,

            gateway_id=None,
            nat_gateway_id=None,
            firewall_rule_id=flow_log['properties']['flows'][0]['rule'],

            source_tags={},
            dest_tags={},
            geo_source=None,
            geo_dest=None,

            raw_event=flow_log
        )

    def normalize_gcp_vpc_flow(self, flow_log: Dict) -> UnifiedNetworkFlow:
        """
        Normalize GCP VPC Flow Log

        GCP Format:
        {
          "insertId": "...",
          "jsonPayload": {
            "connection": {
              "src_ip": "10.128.0.2",
              "src_port": 35970,
              "dest_ip": "142.250.185.46",
              "dest_port": 443,
              "protocol": 6
            },
            "start_time": "2021-12-01T12:00:00.000Z",
            "end_time": "2021-12-01T12:00:10.000Z",
            "bytes_sent": 1234,
            "packets_sent": 10,
            "reporter": "SRC"
          }
        }
        """
        conn = flow_log['jsonPayload']['connection']

        return UnifiedNetworkFlow(
            timestamp=datetime.fromisoformat(flow_log['jsonPayload']['start_time'].replace('Z', '+00:00')),
            source_ip=conn['src_ip'],
            source_port=conn['src_port'],
            dest_ip=conn['dest_ip'],
            dest_port=conn['dest_port'],
            protocol=self._protocol_number_to_name(conn['protocol']),
            bytes_sent=flow_log['jsonPayload'].get('bytes_sent', 0),
            bytes_received=0,
            packets_sent=flow_log['jsonPayload'].get('packets_sent', 0),
            packets_received=0,
            action='ACCEPT',  # GCP flow logs only show accepted

            cloud_provider='gcp',
            region=flow_log.get('resource', {}).get('labels', {}).get('location'),
            vpc_id=flow_log.get('resource', {}).get('labels', {}).get('subnetwork_name'),
            subnet_id=None,

            source_instance_id=None,
            source_resource_type=None,
            dest_instance_id=None,
            dest_resource_type=None,

            gateway_id=None,
            nat_gateway_id=None,
            firewall_rule_id=None,

            source_tags={},
            dest_tags={},
            geo_source=None,
            geo_dest=None,

            raw_event=flow_log
        )

    def normalize_vmware_nsx_flow(self, flow_log: Dict) -> UnifiedNetworkFlow:
        """
        Normalize VMware NSX-T flow log

        NSX-T exports IPFIX/NetFlow or syslog
        """
        return UnifiedNetworkFlow(
            timestamp=datetime.fromtimestamp(flow_log['timestamp']),
            source_ip=flow_log['sourceIPv4Address'],
            source_port=flow_log['sourceTransportPort'],
            dest_ip=flow_log['destinationIPv4Address'],
            dest_port=flow_log['destinationTransportPort'],
            protocol=self._protocol_number_to_name(flow_log['protocolIdentifier']),
            bytes_sent=flow_log['octetDeltaCount'],
            bytes_received=0,
            packets_sent=flow_log['packetDeltaCount'],
            packets_received=0,
            action='ACCEPT',  # Would need DFW logs for drops

            cloud_provider='vmware',
            region=None,
            vpc_id=flow_log.get('nsx_segment_id'),
            subnet_id=None,

            source_instance_id=flow_log.get('source_vm_id'),
            source_resource_type='vm',
            dest_instance_id=flow_log.get('dest_vm_id'),
            dest_resource_type='vm',

            gateway_id=flow_log.get('tier0_gateway_id'),
            nat_gateway_id=None,
            firewall_rule_id=flow_log.get('firewall_rule_id'),

            source_tags=flow_log.get('source_tags', {}),
            dest_tags=flow_log.get('dest_tags', {}),
            geo_source=None,
            geo_dest=None,

            raw_event=flow_log
        )

    def _protocol_number_to_name(self, proto: int) -> str:
        """Convert IANA protocol number to name"""
        protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH'}
        return protocols.get(proto, f'PROTO-{proto}')

    def _extract_azure_region(self, resource_id: str) -> str:
        """Extract region from Azure resource ID"""
        # /subscriptions/{sub}/resourceGroups/{rg}/providers/.../locations/{region}/...
        parts = resource_id.split('/')
        for i, part in enumerate(parts):
            if part == 'locations' and i + 1 < len(parts):
                return parts[i + 1]
        return 'unknown'

    def _extract_azure_vnet(self, resource_id: str) -> str:
        """Extract VNet name from Azure resource ID"""
        parts = resource_id.split('/')
        for i, part in enumerate(parts):
            if part == 'virtualNetworks' and i + 1 < len(parts):
                return parts[i + 1]
        return 'unknown'
```

### 2.3 Multi-Cloud BGP Monitoring

**Cloud Provider BGP Services:**

| Cloud | Service | BGP Capability | Monitoring Approach |
|-------|---------|----------------|---------------------|
| AWS | Direct Connect, Transit Gateway | Customer Gateway BGP, TGW route propagation | CloudWatch Metrics + VPC Flow Logs |
| Azure | ExpressRoute, VPN Gateway | BGP peering with on-prem | Azure Monitor + Network Watcher |
| GCP | Cloud Interconnect, Cloud Router | Dynamic routing via BGP | Stackdriver Logging + VPC Flow Logs |
| Oracle | FastConnect | BGP with on-prem | OCI Logging Analytics |
| VMware NSX-T | Tier-0 Gateway | BGP, OSPF with physical routers | NSX-T API + syslog |
| OpenStack | Neutron dynamic routing | BGP speaker integration | Neutron API + logs |

**Detection Across Clouds:**

```python
class MultiCloudBGPMonitor:
    """Cloud-agnostic BGP monitoring"""

    def detect_cloud_route_hijack(self, cloud_provider: str, route_event: Dict) -> List[BGPAnomaly]:
        """
        Detect BGP route hijacks in cloud environments

        AWS: Unexpected routes in Transit Gateway route table
        Azure: Unauthorized routes in Virtual Hub
        GCP: Anomalous routes in Cloud Router
        """
        anomalies = []

        if cloud_provider == 'aws':
            # Check Transit Gateway route propagation
            if route_event.get('source') == 'propagated':
                # Route came from CGW (Customer Gateway) BGP
                if not self._is_authorized_cgw(route_event['gateway_id']):
                    anomalies.append(BGPAnomaly(
                        anomaly_type='aws_unauthorized_route_propagation',
                        severity='high',
                        confidence=0.85,
                        description=f"Unauthorized route {route_event['cidr']} propagated from CGW {route_event['gateway_id']}",
                        affected_prefixes=[route_event['cidr']],
                        evidence={
                            'cidr': route_event['cidr'],
                            'gateway_id': route_event['gateway_id'],
                            'transit_gateway_id': route_event['tgw_id']
                        },
                        mitre_techniques=['T1498.001'],
                        recommended_action='Verify CGW legitimacy. Disable route propagation if unauthorized.'
                    ))

        elif cloud_provider == 'azure':
            # Check ExpressRoute route advertisements
            if route_event.get('route_origin') == 'ExpressRoute':
                if not self._is_authorized_expressroute(route_event['circuit_id']):
                    anomalies.append(BGPAnomaly(
                        anomaly_type='azure_unauthorized_expressroute_route',
                        severity='high',
                        confidence=0.80,
                        description=f"Unauthorized route {route_event['address_prefix']} from ExpressRoute {route_event['circuit_id']}",
                        affected_prefixes=[route_event['address_prefix']],
                        evidence={
                            'address_prefix': route_event['address_prefix'],
                            'circuit_id': route_event['circuit_id']
                        },
                        mitre_techniques=['T1498.001'],
                        recommended_action='Verify ExpressRoute circuit. Check route filters.'
                    ))

        elif cloud_provider == 'gcp':
            # Check Cloud Router learned routes
            if route_event.get('route_type') == 'DYNAMIC':
                # Compare with known BGP neighbors
                if route_event['next_hop_ip'] not in self.known_bgp_neighbors:
                    anomalies.append(BGPAnomaly(
                        anomaly_type='gcp_unknown_bgp_neighbor',
                        severity='high',
                        confidence=0.75,
                        description=f"Route {route_event['dest_range']} learned from unknown BGP neighbor {route_event['next_hop_ip']}",
                        affected_prefixes=[route_event['dest_range']],
                        evidence={
                            'dest_range': route_event['dest_range'],
                            'next_hop_ip': route_event['next_hop_ip'],
                            'router': route_event['router_name']
                        },
                        mitre_techniques=['T1498.001'],
                        recommended_action='Verify BGP neighbor. Check Cloud Router configuration.'
                    ))

        return anomalies
```

---

## Cloud-Agnostic Connector Architecture

### 3.1 Connector Framework

**Design:** Plugin-based architecture for adding new cloud providers without core code changes.

```python
"""
connector_framework.py - Pluggable cloud connectors
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ConnectorCapabilities:
    """What this connector can collect"""
    supports_flow_logs: bool
    supports_bgp_monitoring: bool
    supports_vpn_tunnels: bool
    supports_firewall_logs: bool
    supports_dns_logs: bool
    real_time: bool  # Streaming vs batch
    authentication_methods: List[str]  # api_key, oauth, service_account, etc.


class CloudConnector(ABC):
    """Base class for all cloud connectors"""

    @abstractmethod
    def get_capabilities(self) -> ConnectorCapabilities:
        """Return what this connector supports"""
        pass

    @abstractmethod
    async def authenticate(self, credentials: Dict[str, Any]) -> bool:
        """Authenticate with cloud provider"""
        pass

    @abstractmethod
    async def collect_flow_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Collect network flow logs"""
        pass

    @abstractmethod
    async def collect_bgp_events(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Collect BGP routing events"""
        pass

    @abstractmethod
    async def collect_vpn_events(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Collect VPN tunnel events"""
        pass

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check connector health"""
        pass


class AWSConnector(CloudConnector):
    """AWS cloud connector"""

    def __init__(self, access_key: str, secret_key: str, region: str):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.session = None

    def get_capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities(
            supports_flow_logs=True,
            supports_bgp_monitoring=True,  # Via CloudWatch metrics
            supports_vpn_tunnels=True,
            supports_firewall_logs=True,  # Network Firewall
            supports_dns_logs=True,  # Route 53 Resolver
            real_time=True,  # EventBridge + Kinesis
            authentication_methods=['access_key', 'iam_role', 'assume_role']
        )

    async def authenticate(self, credentials: Dict[str, Any]) -> bool:
        """Authenticate with AWS"""
        import boto3
        try:
            self.session = boto3.Session(
                aws_access_key_id=credentials['access_key'],
                aws_secret_access_key=credentials['secret_key'],
                region_name=credentials.get('region', 'us-east-1')
            )
            # Test credentials
            sts = self.session.client('sts')
            sts.get_caller_identity()
            return True
        except Exception as e:
            print(f"AWS auth failed: {e}")
            return False

    async def collect_flow_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """
        Collect VPC Flow Logs from CloudWatch Logs or S3

        Methods:
        1. CloudWatch Logs (real-time, expensive)
        2. S3 (batch, cheaper)
        3. Kinesis Data Firehose (streaming)
        """
        logs_client = self.session.client('logs')

        # Find flow log groups
        log_groups = logs_client.describe_log_groups(
            logGroupNamePrefix='/aws/vpc/flowlogs'
        )

        flows = []
        for group in log_groups['logGroups']:
            # Query logs
            query = """
            fields @timestamp, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, action
            | filter action = "REJECT" or bytes > 1000000
            | sort @timestamp desc
            """

            query_id = logs_client.start_query(
                logGroupName=group['logGroupName'],
                startTime=int(start_time.timestamp()),
                endTime=int(end_time.timestamp()),
                queryString=query
            )['queryId']

            # Wait for results
            import time
            while True:
                result = logs_client.get_query_results(queryId=query_id)
                if result['status'] == 'Complete':
                    flows.extend(result['results'])
                    break
                time.sleep(0.5)

        return flows

    async def collect_bgp_events(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """
        Collect BGP events from:
        1. CloudWatch Metrics (Direct Connect/VPN BGP status)
        2. CloudTrail (route table changes)
        """
        cloudwatch = self.session.client('cloudwatch')

        # Get Direct Connect BGP metrics
        bgp_metrics = cloudwatch.get_metric_statistics(
            Namespace='AWS/DX',
            MetricName='ConnectionBpsEgress',
            Dimensions=[{'Name': 'ConnectionId', 'Value': 'dxcon-*'}],
            StartTime=start_time,
            EndTime=end_time,
            Period=60,
            Statistics=['Sum', 'Average']
        )

        return bgp_metrics['Datapoints']

    async def collect_vpn_events(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """
        Collect VPN tunnel events
        """
        ec2 = self.session.client('ec2')

        # Get VPN connections
        vpns = ec2.describe_vpn_connections()

        events = []
        for vpn in vpns['VpnConnections']:
            for tunnel in vpn['VgwTelemetry']:
                events.append({
                    'vpn_id': vpn['VpnConnectionId'],
                    'tunnel_ip': tunnel['OutsideIpAddress'],
                    'status': tunnel['Status'],
                    'status_message': tunnel.get('StatusMessage'),
                    'last_status_change': tunnel.get('LastStatusChange'),
                    'accepted_route_count': tunnel.get('AcceptedRouteCount', 0)
                })

        return events

    async def health_check(self) -> Dict[str, Any]:
        """Check AWS connector health"""
        try:
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            return {
                'status': 'healthy',
                'account_id': identity['Account'],
                'user_arn': identity['Arn']
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }


class AzureConnector(CloudConnector):
    """Azure cloud connector"""

    def get_capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities(
            supports_flow_logs=True,
            supports_bgp_monitoring=True,  # ExpressRoute
            supports_vpn_tunnels=True,
            supports_firewall_logs=True,  # Azure Firewall
            supports_dns_logs=True,  # Private DNS
            real_time=True,  # Event Hubs
            authentication_methods=['service_principal', 'managed_identity']
        )

    async def authenticate(self, credentials: Dict[str, Any]) -> bool:
        """Authenticate with Azure"""
        from azure.identity import ClientSecretCredential
        from azure.mgmt.network import NetworkManagementClient

        try:
            credential = ClientSecretCredential(
                tenant_id=credentials['tenant_id'],
                client_id=credentials['client_id'],
                client_secret=credentials['client_secret']
            )

            # Test with network client
            network_client = NetworkManagementClient(
                credential, credentials['subscription_id']
            )
            list(network_client.virtual_networks.list_all())  # Test API call

            self.credential = credential
            self.subscription_id = credentials['subscription_id']
            return True
        except Exception as e:
            print(f"Azure auth failed: {e}")
            return False

    async def collect_flow_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """
        Collect NSG Flow Logs from:
        1. Azure Storage Account (batch)
        2. Log Analytics Workspace (query)
        3. Event Hubs (streaming)
        """
        from azure.monitor.query import LogsQueryClient

        logs_client = LogsQueryClient(self.credential)

        # Query Log Analytics
        query = """
        AzureNetworkAnalytics_CL
        | where TimeGenerated between(datetime({start}) .. datetime({end}))
        | where SubType_s == "FlowLog"
        | project TimeGenerated, SrcIP_s, DestIP_s, SrcPort_d, DestPort_d, L7Protocol_s, FlowStatus_s
        """.format(start=start_time.isoformat(), end=end_time.isoformat())

        response = logs_client.query_workspace(
            workspace_id=self.workspace_id,
            query=query,
            timespan=(start_time, end_time)
        )

        return response.tables[0].rows if response.tables else []

    # ... similar methods for BGP, VPN, health_check


class GCPConnector(CloudConnector):
    """Google Cloud Platform connector"""

    def get_capabilities(self) -> ConnectorCapabilities:
        return ConnectorCapabilities(
            supports_flow_logs=True,
            supports_bgp_monitoring=True,  # Cloud Router
            supports_vpn_tunnels=True,
            supports_firewall_logs=True,  # VPC Firewall Rules
            supports_dns_logs=True,  # Cloud DNS
            real_time=True,  # Pub/Sub
            authentication_methods=['service_account_json', 'application_default']
        )

    async def authenticate(self, credentials: Dict[str, Any]) -> bool:
        """Authenticate with GCP"""
        from google.oauth2 import service_account
        from google.cloud import logging_v2

        try:
            creds = service_account.Credentials.from_service_account_file(
                credentials['service_account_json_path']
            )

            # Test with logging client
            client = logging_v2.Client(credentials=creds, project=credentials['project_id'])
            list(client.list_entries(page_size=1))  # Test API call

            self.credentials = creds
            self.project_id = credentials['project_id']
            return True
        except Exception as e:
            print(f"GCP auth failed: {e}")
            return False

    async def collect_flow_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """
        Collect VPC Flow Logs from Cloud Logging
        """
        from google.cloud import logging_v2

        client = logging_v2.Client(credentials=self.credentials, project=self.project_id)

        filter_str = f'''
        resource.type="gce_subnetwork"
        logName="projects/{self.project_id}/logs/compute.googleapis.com%2Fvpc_flows"
        timestamp>="{start_time.isoformat()}Z"
        timestamp<"{end_time.isoformat()}Z"
        '''

        entries = client.list_entries(filter_=filter_str)

        flows = []
        for entry in entries:
            flows.append(entry.to_api_repr())

        return flows

    # ... similar methods for BGP, VPN, health_check


# Connector registry
CONNECTOR_REGISTRY = {
    'aws': AWSConnector,
    'azure': AzureConnector,
    'gcp': GCPConnector,
    # Add more as needed:
    # 'oracle': OracleCloudConnector,
    # 'vmware': VMwareNSXConnector,
    # 'openstack': OpenStackConnector,
    # 'hpe': HPEGreenLakeConnector,
}


def get_connector(cloud_provider: str, credentials: Dict[str, Any]) -> CloudConnector:
    """Factory function to get appropriate connector"""
    connector_class = CONNECTOR_REGISTRY.get(cloud_provider.lower())
    if not connector_class:
        raise ValueError(f"Unsupported cloud provider: {cloud_provider}")

    return connector_class(**credentials)
```

### 3.2 API/Webhook Integration Matrix

| Cloud Provider | Real-Time Method | Batch Method | Configuration |
|----------------|------------------|--------------|---------------|
| **AWS** | EventBridge → Lambda → JanuSec webhook | S3 bucket → periodic poll | EventBridge rule pattern-match on VPC Flow Log, CloudTrail |
| **Azure** | Event Hubs → JanuSec consumer | Storage Account → poll | Event Hub subscription to NSG Flow Logs, Diagnostic Settings |
| **GCP** | Pub/Sub → JanuSec subscriber | Cloud Storage → poll | Log sink to Pub/Sub topic, JanuSec subscriber |
| **Oracle Cloud** | Event Service → webhook | Object Storage → poll | Event rules for VCN flow logs |
| **VMware NSX-T** | Webhook notifications | NSX-T API periodic poll | NSX-T event subscriptions |
| **OpenStack** | Notification bus (RabbitMQ) → consumer | Neutron API poll | Configure notification driver |
| **Private (syslog)** | Syslog TCP/UDP stream | Log file ingestion | Point routers' syslog to JanuSec collector |

---

## Data Ingestion Pipeline

### 9.1 Live vs Manual Ingestion

**Architecture:**

```
┌─────────────────────────────────────────────────────────────────────┐
│                    JANUSEC DATA INGESTION PIPELINE                   │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ LIVE INGESTION (Real-Time)                                           │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  [Cloud Provider]                                                    │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │ Event Stream│ (EventBridge, Event Hubs, Pub/Sub)                  │
│  └─────────────┘                                                     │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │  Webhook /  │ JanuSec Ingestion Endpoint                          │
│  │  Subscriber │ POST /api/v1/ingest/network_events                  │
│  └─────────────┘                                                     │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │ Normalizer  │ cloud_network_normalizer.normalize()                │
│  └─────────────┘                                                     │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │ Enrichment  │ Geo IP, Threat Intel, Asset tags                    │
│  └─────────────┘                                                     │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │ Detection   │ BGP/OSPF/IPsec monitors                             │
│  └─────────────┘                                                     │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │  HopGraph   │ Add network nodes + edges                           │
│  └─────────────┘                                                     │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │ Alert Queue │ If anomaly detected → Tier 1 LLM                    │
│  └─────────────┘                                                     │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│ MANUAL INGESTION (Batch/On-Demand)                                   │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  [User uploads CSV/JSON/syslog file]                                 │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │   Upload    │ POST /api/v1/assessments/deep_analyze               │
│  │   Endpoint  │ (multipart/form-data)                               │
│  └─────────────┘                                                     │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │   Parser    │ Detect format (CSV, JSON, syslog, PCAP)             │
│  └─────────────┘                                                     │
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │ Normalizer  │ Map columns → UnifiedNetworkFlow                    │
│  └─────────────┘                                                     │
│         ↓                                                            │
│  [Same pipeline as Live Ingestion: Enrichment → Detection → HopGraph]│
│         ↓                                                            │
│  ┌─────────────┐                                                     │
│  │  Generate   │ csv_deep_analysis.html report with                  │
│  │   Report    │ network-specific insights                           │
│  └─────────────┘                                                     │
└──────────────────────────────────────────────────────────────────────┘
```

### 9.2 Per-Row Network Enrichment

**Enhancement to CSV Analysis:**

```python
"""
network_row_enrichment.py - Enrich each network event row
"""

async def enrich_network_row(row: UnifiedNetworkFlow, enrichment_level: str = 'full') -> Dict[str, Any]:
    """
    Enrich network flow with threat intel, geo, ASN, reputation

    Args:
        row: Normalized network flow
        enrichment_level: 'minimal', 'standard', 'full'

    Returns:
        Enriched data dictionary
    """
    enriched = {
        'original': row,
        'enrichments': {}
    }

    # Level 1: Minimal (always included, cached, fast)
    enriched['enrichments']['geo_source'] = await get_geo_ip(row.source_ip)  # Cached MaxMind
    enriched['enrichments']['geo_dest'] = await get_geo_ip(row.dest_ip)
    enriched['enrichments']['source_asn'] = await get_asn(row.source_ip)
    enriched['enrichments']['dest_asn'] = await get_asn(row.dest_ip)

    # Level 2: Standard (threat intel, budget-gated)
    if enrichment_level in ['standard', 'full']:
        enriched['enrichments']['source_reputation'] = await check_ip_reputation(row.source_ip)
        enriched['enrichments']['dest_reputation'] = await check_ip_reputation(row.dest_ip)
        enriched['enrichments']['domain_reputation'] = await check_domain_reputation(row.dest_ip)

    # Level 3: Full (expensive lookups, analyst-triggered)
    if enrichment_level == 'full':
        enriched['enrichments']['threat_intel'] = await query_threat_intel(row.source_ip, row.dest_ip)
        enriched['enrichments']['historical_behavior'] = await get_ip_history(row.source_ip)
        enriched['enrichments']['related_incidents'] = await find_related_incidents(row)

    # Network-specific enrichments
    enriched['enrichments']['port_classification'] = classify_port(row.dest_port)
    enriched['enrichments']['protocol_risk'] = assess_protocol_risk(row.protocol, row.dest_port)

    # Cloud-specific enrichments
    if row.cloud_provider:
        enriched['enrichments']['resource_tags'] = row.source_tags
        enriched['enrichments']['compliance_zone'] = classify_compliance_zone(row.vpc_id, row.cloud_provider)

    # BGP-specific (if this is a BGP event)
    if hasattr(row, 'as_path'):
        enriched['enrichments']['as_path_analysis'] = analyze_as_path(row.as_path)
        enriched['enrichments']['rpki_validation'] = await validate_rpki(row.prefix, row.origin_asn)

    return enriched


def classify_port(port: int) -> Dict[str, Any]:
    """Classify destination port by service and risk"""
    WELL_KNOWN_PORTS = {
        20: {'service': 'FTP-DATA', 'risk': 'medium', 'category': 'file_transfer'},
        21: {'service': 'FTP', 'risk': 'high', 'category': 'file_transfer', 'note': 'Cleartext, use SFTP'},
        22: {'service': 'SSH', 'risk': 'low', 'category': 'remote_access'},
        23: {'service': 'Telnet', 'risk': 'critical', 'category': 'remote_access', 'note': 'Cleartext, use SSH'},
        25: {'service': 'SMTP', 'risk': 'medium', 'category': 'email'},
        53: {'service': 'DNS', 'risk': 'low', 'category': 'infrastructure'},
        80: {'service': 'HTTP', 'risk': 'medium', 'category': 'web', 'note': 'Cleartext, use HTTPS'},
        443: {'service': 'HTTPS', 'risk': 'low', 'category': 'web'},
        445: {'service': 'SMB', 'risk': 'high', 'category': 'file_sharing', 'note': 'Common ransomware vector'},
        3389: {'service': 'RDP', 'risk': 'high', 'category': 'remote_access', 'note': 'Brute-force target'},
        # ... (add more)
    }

    if port in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[port]
    elif port < 1024:
        return {'service': f'Reserved-{port}', 'risk': 'medium', 'category': 'system'}
    elif 1024 <= port < 49152:
        return {'service': f'Registered-{port}', 'risk': 'low', 'category': 'application'}
    else:
        return {'service': f'Dynamic-{port}', 'risk': 'low', 'category': 'ephemeral'}


def assess_protocol_risk(protocol: str, dest_port: int) -> str:
    """Assess risk based on protocol + port combination"""
    # High-risk combinations
    if protocol == 'TCP' and dest_port == 23:  # Telnet
        return 'critical'
    elif protocol == 'TCP' and dest_port == 3389:  # RDP over internet
        return 'high'
    elif protocol == 'TCP' and dest_port in [445, 139]:  # SMB
        return 'high'
    elif protocol == 'UDP' and dest_port == 161:  # SNMP
        return 'medium'
    else:
        return 'low'
```

---

## Tier 1/Tier 2 LLM Enrichment

### 11.1 Network-Aware LLM Context

**Enhanced Tier 1 Prompt:**

```python
def generate_tier1_network_summary(network_events: List[UnifiedNetworkFlow], anomalies: List[Any]) -> str:
    """
    Generate Tier 1 LLM summary with network context
    """

    # Build context
    total_flows = len(network_events)
    unique_sources = len(set(e.source_ip for e in network_events))
    unique_dests = len(set(e.dest_ip for e in network_events))
    total_bytes = sum(e.bytes_sent for e in network_events)

    # Identify top talkers
    from collections import Counter
    dest_ports = Counter(e.dest_port for e in network_events)
    top_ports = dest_ports.most_common(5)

    # Cloud context
    cloud_providers = set(e.cloud_provider for e in network_events if e.cloud_provider)

    # Anomaly summary
    anomaly_types = Counter(a.anomaly_type for a in anomalies)

    prompt = f"""
You are a Tier 1 SOC analyst summarizing network security events for initial triage.

## Network Activity Summary
- **Total Flows:** {total_flows:,}
- **Unique Source IPs:** {unique_sources}
- **Unique Destination IPs:** {unique_dests}
- **Total Data Transferred:** {total_bytes / 1024 / 1024:.2f} MB
- **Cloud Providers:** {', '.join(cloud_providers) if cloud_providers else 'On-premises'}

## Top Destination Ports
{chr(10).join(f'- Port {port}: {count} flows ({classify_port(port)["service"]})' for port, count in top_ports)}

## Detected Anomalies ({len(anomalies)} total)
{chr(10).join(f'- {atype}: {count}' for atype, count in anomaly_types.most_common())}

## Sample Anomaly Details
{chr(10).join(f'- **{a.severity.upper()}:** {a.description}' for a in anomalies[:3])}

---

**Task:** Provide a 3-sentence executive summary for Tier 1 triage. Focus on:
1. What network activity occurred (normal vs suspicious)
2. Severity assessment (critical, high, medium, low)
3. Recommended next action (escalate to Tier 2, false positive, investigate specific IP)

**Output Format:**
Summary: [Your 3-sentence summary]
Severity: [critical|high|medium|low]
Recommendation: [escalate|investigate|false_positive]
"""

    return prompt


def generate_tier2_network_investigation(
    network_events: List[UnifiedNetworkFlow],
    anomalies: List[Any],
    tier1_summary: str,
    hopgraph_path: List[Dict]
) -> str:
    """
    Generate Tier 2 LLM prompt with deep network analysis
    """

    # Build detailed context
    bgp_anomalies = [a for a in anomalies if 'bgp' in a.anomaly_type.lower()]
    ospf_anomalies = [a for a in anomalies if 'ospf' in a.anomaly_type.lower()]
    ipsec_anomalies = [a for a in anomalies if 'ipsec' in a.anomaly_type.lower()]
    vxlan_anomalies = [a for a in anomalies if 'vxlan' in a.anomaly_type.lower()]

    # Network flow analysis
    suspicious_flows = [e for e in network_events if e.dest_port in [23, 3389, 445] or e.bytes_sent > 100_000_000]

    # Geo analysis
    countries_src = set(e.geo_source.get('country') for e in network_events if e.geo_source)
    countries_dst = set(e.geo_dest.get('country') for e in network_events if e.geo_dest)

    prompt = f"""
You are a Tier 2 SOC analyst conducting deep investigation of network security incidents.

## Tier 1 Summary
{tier1_summary}

## Deep Network Analysis

### Routing Protocol Anomalies
**BGP Issues ({len(bgp_anomalies)}):**
{chr(10).join(f'- {a.description}' for a in bgp_anomalies[:5])}

**OSPF Issues ({len(ospf_anomalies)}):**
{chr(10).join(f'- {a.description}' for a in ospf_anomalies[:5])}

**IPsec/VPN Issues ({len(ipsec_anomalies)}):**
{chr(10).join(f'- {a.description}' for a in ipsec_anomalies[:5])}

**VXLAN/Overlay Issues ({len(vxlan_anomalies)}):**
{chr(10).join(f'- {a.description}' for a in vxlan_anomalies[:5])}

### Suspicious Network Flows ({len(suspicious_flows)})
{chr(10).join(f'- {e.source_ip}:{e.source_port} → {e.dest_ip}:{e.dest_port} ({e.bytes_sent / 1024 / 1024:.2f} MB, {classify_port(e.dest_port)["service"]})' for e in suspicious_flows[:10])}

### Geographic Distribution
- **Source Countries:** {', '.join(countries_src)}
- **Destination Countries:** {', '.join(countries_dst)}

### Attack Path (HopGraph)
```
{chr(10).join(f'{i+1}. {node["type"]}: {node["id"]} ({node.get("description", "")})' for i, node in enumerate(hopgraph_path))}
```

---

**Task:** Provide comprehensive Tier 2 analysis including:

1. **Incident Classification:**
   - Incident type (BGP hijack, route leak, VXLAN escape, IPsec MITM, etc.)
   - Attack sophistication (nation-state, APT, opportunistic, misconfiguration)
   - Impact assessment (data exfiltration, service disruption, reconnaissance)

2. **Root Cause Analysis:**
   - How did the attack occur? (specific misconfiguration, vulnerability, etc.)
   - Attack timeline reconstruction

3. **Indicators of Compromise:**
   - Malicious IPs/ASNs
   - Compromised network devices
   - Suspicious routing changes

4. **Containment Actions:**
   - Immediate steps to stop ongoing attack
   - Specific commands/configurations to implement

5. **Remediation:**
   - Long-term fixes (enable RPKI, harden IPsec, segment VXLAN)
   - Preventive measures

6. **Compliance Impact:**
   - Regulatory implications (GDPR, HIPAA, PCI-DSS if applicable)
   - Data breach notification requirements

**Output Format (JSON):**
```json
{{
  "incident_type": "...",
  "severity": "critical|high|medium|low",
  "sophistication": "...",
  "impact": "...",
  "root_cause": "...",
  "timeline": ["...", "..."],
  "iocs": {{"ips": [], "asns": [], "domains": []}},
  "containment": ["...", "..."],
  "remediation": ["...", "..."],
  "compliance_impact": "..."
}}
```
"""

    return prompt
```

### 11.2 Gated LLM Summaries (Cost Control)

**Tier 1 Gates:**
```python
def should_trigger_tier1_llm(network_events: List[UnifiedNetworkFlow], anomalies: List[Any]) -> bool:
    """
    Decide if network events warrant Tier 1 LLM summary

    Gates:
    1. Any critical anomalies (BGP hijack, OSPF poisoning, etc.)
    2. High-volume data transfer (>1GB)
    3. Traffic to high-risk ports (Telnet, RDP to internet)
    4. Multiple anomaly types (suggests coordinated attack)
    """
    # Gate 1: Critical anomalies always trigger
    critical_anomalies = [a for a in anomalies if a.severity == 'critical']
    if critical_anomalies:
        return True

    # Gate 2: High-volume exfiltration
    total_bytes = sum(e.bytes_sent for e in network_events)
    if total_bytes > 1_000_000_000:  # >1GB
        return True

    # Gate 3: High-risk traffic
    high_risk_flows = [e for e in network_events if e.dest_port in [23, 3389] and is_external(e.dest_ip)]
    if len(high_risk_flows) > 10:
        return True

    # Gate 4: Multiple anomaly types (coordinated attack)
    anomaly_types = set(a.anomaly_type for a in anomalies)
    if len(anomaly_types) >= 3:
        return True

    # Gate 5: Multiple high-severity anomalies
    high_anomalies = [a for a in anomalies if a.severity == 'high']
    if len(high_anomalies) >= 5:
        return True

    return False  # Don't spend LLM cost on low-signal events
```

**Tier 2 Gates:**
```python
def should_escalate_to_tier2(tier1_result: Dict, analyst_feedback: Optional[Dict] = None) -> bool:
    """
    Decide if Tier 1 alert should escalate to Tier 2 (expensive LLM + human time)

    Gates:
    1. Tier 1 recommended escalation
    2. Analyst manually escalated
    3. Confirmed BGP/OSPF attack
    4. Multi-stage attack detected
    """
    # Gate 1: Tier 1 LLM recommendation
    if tier1_result.get('recommendation') == 'escalate':
        return True

    # Gate 2: Analyst override
    if analyst_feedback and analyst_feedback.get('action') == 'escalate':
        return True

    # Gate 3: Confirmed network infrastructure attack
    confirmed_attacks = ['bgp_hijack', 'ospf_lsa_flood', 'ipsec_crypto_downgrade', 'vxlan_rogue_vtep']
    if any(attack in tier1_result.get('anomaly_types', []) for attack in confirmed_attacks):
        return True

    # Gate 4: Multi-domain attack (network + endpoint + cloud)
    if tier1_result.get('cross_domain_attack'):
        return True

    return False
```

---

## SOC Analyst Tooling

### 12.1 Network Investigation Workbench

**UI Component: `network_investigation.html`**

```html
<!-- Quick Investigation Panel -->
<div class="investigation-workbench">
  <h3>🔍 Network Investigation: BGP Hijack (INC-2025-1234)</h3>

  <!-- Quick Actions -->
  <div class="quick-actions">
    <button onclick="runWhois()">🌐 WHOIS Lookup</button>
    <button onclick="runTraceroute()">🛤️ Traceroute</button>
    <button onclick="checkRPKI()">🔐 RPKI Validation</button>
    <button onclick="queryBGPmon()">📡 BGPmon History</button>
    <button onclick="runASNLookup()">🏢 ASN Info</button>
    <button onclick="checkPeerDB()">🤝 PeeringDB</button>
  </div>

  <!-- Investigation Findings -->
  <div id="findings">
    <!-- Populated by tool results -->
  </div>

  <!-- Playbook Suggestions -->
  <div class="playbook-suggestions">
    <h4>📋 Suggested Playbooks</h4>
    <ul>
      <li onclick="runPlaybook('bgp_hijack_response')">
        🚨 BGP Hijack Response
        <span class="playbook-desc">Contact ISP, RPKI validation, counter-hijack</span>
      </li>
      <li onclick="runPlaybook('route_leak_containment')">
        🔒 Route Leak Containment
        <span class="playbook-desc">Filter leaked routes, update route maps</span>
      </li>
    </ul>
  </div>
</div>
```

**Backend Tools:**

```python
"""
soc_network_tools.py - Investigation tools for SOC analysts
"""

class NetworkInvestigationTools:
    """Tools for network security investigation"""

    async def whois_lookup(self, ip_or_asn: str) -> Dict[str, Any]:
        """
        WHOIS lookup for IP or ASN

        Returns org, abuse contact, CIDR range
        """
        import whois
        result = whois.whois(ip_or_asn)
        return {
            'org': result.org,
            'abuse_email': result.emails[0] if result.emails else None,
            'cidr': result.cidr,
            'country': result.country,
            'created': result.creation_date,
            'updated': result.updated_date
        }

    async def rpki_validation(self, prefix: str, origin_asn: int) -> Dict[str, Any]:
        """
        Validate route against RPKI

        Uses RIPE RPKI validator API
        """
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                'https://rpki-validator.ripe.net/api/v1/validity',
                params={'prefix': prefix, 'asn': f'AS{origin_asn}'}
            )
            data = response.json()

        return {
            'valid': data['validated_route']['validity']['state'] == 'Valid',
            'state': data['validated_route']['validity']['state'],
            'reason': data['validated_route']['validity'].get('reason'),
            'roas': data.get('roas', [])
        }

    async def bgpmon_history(self, prefix: str, hours: int = 24) -> List[Dict]:
        """
        Query BGPmon for prefix hijack history

        Returns historical BGP announcements
        """
        # Placeholder - would integrate with BGPmon API or RIS
        return [
            {
                'timestamp': '2025-11-30T14:32:00Z',
                'event': 'announcement',
                'prefix': prefix,
                'origin_asn': 666,
                'as_path': [64600, 666],
                'peer': '203.0.113.1'
            }
        ]

    async def asn_lookup(self, asn: int) -> Dict[str, Any]:
        """
        Lookup ASN information

        Uses RIPE Stat or Team Cymru
        """
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f'https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}'
            )
            data = response.json()['data']

        return {
            'asn': asn,
            'holder': data['holder'],
            'announced': data.get('announced'),
            'country': data.get('country'),
            'rir': data.get('rir'),
            'abuse_contacts': data.get('abuse_contacts', [])
        }

    async def peeringdb_lookup(self, asn: int) -> Dict[str, Any]:
        """
        Query PeeringDB for ASN peering info

        Returns IXPs, peering policy, NOC contacts
        """
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f'https://www.peeringdb.com/api/net?asn={asn}'
            )
            data = response.json()['data'][0] if response.json()['data'] else {}

        return {
            'name': data.get('name'),
            'policy_general': data.get('policy_general'),
            'policy_url': data.get('policy_url'),
            'ix_count': len(data.get('netixlan_set', [])),
            'fac_count': len(data.get('netfac_set', [])),
            'notes': data.get('notes')
        }

    async def traceroute(self, dest_ip: str, source: str = 'auto') -> List[Dict]:
        """
        Run traceroute from JanuSec sensor or cloud probe

        Returns hop-by-hop path
        """
        import subprocess
        result = subprocess.run(
            ['traceroute', '-n', '-m', '30', dest_ip],
            capture_output=True,
            text=True,
            timeout=60
        )

        hops = []
        for line in result.stdout.split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                hops.append({
                    'hop': int(parts[0]),
                    'ip': parts[1] if parts[1] != '*' else None,
                    'rtt_ms': float(parts[2]) if len(parts) > 2 and parts[2] != '*' else None
                })

        return hops
```

---

## Threat Hunter Capabilities

### 13.1 Hunt Queries for Network Infrastructure

**Pre-built Hunt Queries:**

```python
NETWORK_HUNT_QUERIES = {
    'bgp_hijack_campaign': {
        'name': 'BGP Hijack Campaign Detection',
        'description': 'Find prefixes hijacked by same ASN over time',
        'query': '''
            SELECT
                origin_asn,
                COUNT(DISTINCT prefix) as hijacked_prefixes,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                ARRAY_AGG(DISTINCT prefix) as prefixes
            FROM bgp_anomalies
            WHERE anomaly_type = 'prefix_hijack'
              AND timestamp > NOW() - INTERVAL '30 days'
            GROUP BY origin_asn
            HAVING COUNT(DISTINCT prefix) >= 3
            ORDER BY hijacked_prefixes DESC
        ''',
        'threat_level': 'critical',
        'mitre': ['T1498.001']
    },

    'vpn_tunnel_crypto_downgrade_pattern': {
        'name': 'Systematic VPN Crypto Downgrade',
        'description': 'Detect pattern of IPsec tunnels being downgraded',
        'query': '''
            SELECT
                remote_ip,
                COUNT(*) as downgrade_count,
                ARRAY_AGG(tunnel_id) as affected_tunnels,
                MIN(timestamp) as first_downgrade,
                MAX(timestamp) as last_downgrade
            FROM ipsec_anomalies
            WHERE anomaly_type = 'crypto_downgrade'
              AND timestamp > NOW() - INTERVAL '7 days'
            GROUP BY remote_ip
            HAVING COUNT(*) >= 2
        ''',
        'threat_level': 'high',
        'mitre': ['T1600.001', 'T1557']
    },

    'vxlan_isolation_bypass_attempts': {
        'name': 'VXLAN Segment Isolation Bypass',
        'description': 'Find MACs appearing on multiple VNIs (isolation bypass)',
        'query': '''
            SELECT
                mac_address,
                ARRAY_AGG(DISTINCT vni) as vnis,
                COUNT(DISTINCT vni) as vni_count,
                COUNT(*) as event_count
            FROM vxlan_events
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY mac_address
            HAVING COUNT(DISTINCT vni) > 1
        ''',
        'threat_level': 'critical',
        'mitre': ['T1599.001']  # VLAN hopping equivalent
    },

    'east_west_lateral_movement': {
        'name': 'East-West Lateral Movement via Network',
        'description': 'Detect unusual inter-VLAN/VPC traffic patterns',
        'query': '''
            WITH source_stats AS (
                SELECT
                    source_ip,
                    COUNT(DISTINCT dest_ip) as unique_dests,
                    COUNT(DISTINCT dest_port) as unique_ports,
                    SUM(bytes_sent) as total_bytes
                FROM network_flows
                WHERE timestamp > NOW() - INTERVAL '1 hour'
                  AND source_vpc_id = dest_vpc_id  -- Same VPC (lateral)
                GROUP BY source_ip
            )
            SELECT * FROM source_stats
            WHERE unique_dests > 20 OR unique_ports > 15
            ORDER BY unique_dests DESC
        ''',
        'threat_level': 'high',
        'mitre': ['T1021']  # Remote Services
    },

    'dns_tunneling_over_vpn': {
        'name': 'DNS Tunneling Over VPN',
        'description': 'Detect DNS exfiltration through VPN tunnels',
        'query': '''
            SELECT
                source_ip,
                dest_ip,
                COUNT(*) as dns_queries,
                SUM(bytes_sent) as total_bytes,
                AVG(bytes_sent) as avg_query_size
            FROM network_flows
            WHERE dest_port = 53
              AND gateway_type = 'vpn'
              AND timestamp > NOW() - INTERVAL '1 hour'
            GROUP BY source_ip, dest_ip
            HAVING AVG(bytes_sent) > 512  -- Unusually large DNS queries
               AND COUNT(*) > 100  -- High volume
        ''',
        'threat_level': 'high',
        'mitre': ['T1048.003', 'T1071.004']  # Exfil over C2, DNS
    }
}
```

**Hunt Workflow UI:**

```html
<!-- Threat Hunt Dashboard -->
<div class="hunt-dashboard">
  <h2>🎯 Network Threat Hunting</h2>

  <!-- Pre-built Hunts -->
  <div class="hunt-library">
    <h3>Hunt Library</h3>
    <div class="hunt-card" onclick="runHunt('bgp_hijack_campaign')">
      <span class="hunt-icon">🌐</span>
      <h4>BGP Hijack Campaign Detection</h4>
      <p>Find prefixes hijacked by same ASN over time</p>
      <span class="hunt-tag critical">CRITICAL</span>
    </div>

    <div class="hunt-card" onclick="runHunt('vpn_tunnel_crypto_downgrade_pattern')">
      <span class="hunt-icon">🔐</span>
      <h4>Systematic VPN Crypto Downgrade</h4>
      <p>Detect pattern of IPsec tunnels being downgraded</p>
      <span class="hunt-tag high">HIGH</span>
    </div>

    <!-- More hunt cards... -->
  </div>

  <!-- Custom Hunt Builder -->
  <div class="custom-hunt">
    <h3>Custom Hunt</h3>
    <textarea id="customQuery" placeholder="SELECT * FROM network_flows WHERE..."></textarea>
    <button onclick="runCustomHunt()">Execute Hunt</button>
  </div>

  <!-- Hunt Results -->
  <div id="huntResults">
    <!-- Populated after hunt execution -->
  </div>
</div>
```

---

## 14. Forensic Analysis Tools for Network Incidents

When network infrastructure attacks occur (BGP hijacks, route leaks, IPsec compromises), forensic analysts need specialized tools to reconstruct attack timelines, collect evidence, and establish chain of custody.

### 14.1 Network Packet Capture Analysis

```python
"""
network_forensics.py - Network incident forensic analysis
"""
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from datetime import datetime
import dpkt
import hashlib
import json


@dataclass
class ForensicEvidence:
    """Chain of custody for network evidence"""
    evidence_id: str
    incident_id: str
    collection_timestamp: datetime
    collector: str  # Analyst who collected evidence
    source: str  # PCAP file, flow log, syslog
    hash_sha256: str
    preservation_method: str  # encrypted_s3, evidence_locker, tape_backup
    chain_of_custody: List[Dict[str, Any]]  # Transfers between analysts
    analysis_notes: List[Dict[str, Any]]


class NetworkForensicsEngine:
    """Forensic analysis for network incidents"""

    async def analyze_pcap(
        self,
        pcap_path: str,
        incident_id: str,
        focus: str = 'all'  # 'bgp', 'ipsec', 'vxlan', 'all'
    ) -> Dict[str, Any]:
        """
        Parse PCAP and extract network infrastructure attack evidence.

        Args:
            pcap_path: Path to PCAP file
            incident_id: Related incident ID for chain of custody
            focus: Protocol to focus analysis on

        Returns:
            Forensic analysis report with timeline, IOCs, evidence
        """
        # Calculate PCAP hash for chain of custody
        with open(pcap_path, 'rb') as f:
            pcap_hash = hashlib.sha256(f.read()).hexdigest()

        # Create forensic evidence record
        evidence = ForensicEvidence(
            evidence_id=f"EVD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            incident_id=incident_id,
            collection_timestamp=datetime.utcnow(),
            collector="forensics_engine",
            source=pcap_path,
            hash_sha256=pcap_hash,
            preservation_method="encrypted_s3",
            chain_of_custody=[{
                'timestamp': datetime.utcnow().isoformat(),
                'action': 'collected',
                'by': 'forensics_engine',
                'hash_verified': True
            }],
            analysis_notes=[]
        )

        # Parse PCAP
        flows = []
        bgp_updates = []
        ipsec_packets = []
        vxlan_packets = []

        with open(pcap_path, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data

                        # BGP (port 179)
                        if isinstance(ip.data, dpkt.tcp.TCP):
                            tcp = ip.data
                            if tcp.sport == 179 or tcp.dport == 179:
                                bgp_updates.append({
                                    'timestamp': datetime.fromtimestamp(timestamp),
                                    'src_ip': self._ip_to_str(ip.src),
                                    'dst_ip': self._ip_to_str(ip.dst),
                                    'tcp_flags': tcp.flags,
                                    'payload_len': len(tcp.data)
                                })

                        # IPsec (ESP protocol 50, AH protocol 51)
                        if ip.p == 50 or ip.p == 51:
                            ipsec_packets.append({
                                'timestamp': datetime.fromtimestamp(timestamp),
                                'src_ip': self._ip_to_str(ip.src),
                                'dst_ip': self._ip_to_str(ip.dst),
                                'protocol': 'ESP' if ip.p == 50 else 'AH',
                                'spi': ip.data[:4].hex() if len(ip.data) >= 4 else None
                            })

                        # VXLAN (UDP port 4789)
                        if isinstance(ip.data, dpkt.udp.UDP):
                            udp = ip.data
                            if udp.dport == 4789:
                                vxlan_packets.append({
                                    'timestamp': datetime.fromtimestamp(timestamp),
                                    'src_ip': self._ip_to_str(ip.src),
                                    'dst_ip': self._ip_to_str(ip.dst),
                                    'src_port': udp.sport,
                                    'vni': int.from_bytes(udp.data[4:7], 'big') if len(udp.data) >= 7 else None
                                })

                except Exception as e:
                    evidence.analysis_notes.append({
                        'timestamp': datetime.utcnow().isoformat(),
                        'type': 'parse_error',
                        'message': str(e)
                    })

        # Build forensic timeline
        timeline = self._build_attack_timeline(
            bgp_updates, ipsec_packets, vxlan_packets, focus
        )

        # Extract IOCs
        iocs = self._extract_network_iocs(
            bgp_updates, ipsec_packets, vxlan_packets
        )

        return {
            'evidence': evidence,
            'timeline': timeline,
            'iocs': iocs,
            'statistics': {
                'total_bgp_updates': len(bgp_updates),
                'total_ipsec_packets': len(ipsec_packets),
                'total_vxlan_packets': len(vxlan_packets)
            }
        }

    def _ip_to_str(self, ip_bytes: bytes) -> str:
        """Convert IP bytes to string"""
        return '.'.join(str(b) for b in ip_bytes)

    def _build_attack_timeline(
        self,
        bgp_updates: List[Dict],
        ipsec_packets: List[Dict],
        vxlan_packets: List[Dict],
        focus: str
    ) -> List[Dict[str, Any]]:
        """Build chronological attack timeline"""
        events = []

        # BGP timeline
        if focus in ['all', 'bgp'] and bgp_updates:
            first_bgp = min(bgp_updates, key=lambda x: x['timestamp'])
            last_bgp = max(bgp_updates, key=lambda x: x['timestamp'])
            events.append({
                'timestamp': first_bgp['timestamp'],
                'event_type': 'bgp_activity_start',
                'description': f"BGP session activity detected from {first_bgp['src_ip']}"
            })
            events.append({
                'timestamp': last_bgp['timestamp'],
                'event_type': 'bgp_activity_end',
                'description': f"BGP session activity ended"
            })

        # IPsec timeline
        if focus in ['all', 'ipsec'] and ipsec_packets:
            first_ipsec = min(ipsec_packets, key=lambda x: x['timestamp'])
            events.append({
                'timestamp': first_ipsec['timestamp'],
                'event_type': 'ipsec_tunnel_detected',
                'description': f"IPsec tunnel detected: {first_ipsec['src_ip']} → {first_ipsec['dst_ip']}"
            })

        # VXLAN timeline
        if focus in ['all', 'vxlan'] and vxlan_packets:
            unique_vnis = set(p['vni'] for p in vxlan_packets if p['vni'])
            events.append({
                'timestamp': vxlan_packets[0]['timestamp'],
                'event_type': 'vxlan_overlay_detected',
                'description': f"VXLAN overlay network detected with {len(unique_vnis)} VNIs"
            })

        # Sort chronologically
        events.sort(key=lambda x: x['timestamp'])
        return events

    def _extract_network_iocs(
        self,
        bgp_updates: List[Dict],
        ipsec_packets: List[Dict],
        vxlan_packets: List[Dict]
    ) -> Dict[str, List[str]]:
        """Extract indicators of compromise"""
        iocs = {
            'bgp_peer_ips': list(set(u['src_ip'] for u in bgp_updates)),
            'ipsec_endpoints': list(set(
                p['src_ip'] for p in ipsec_packets
            ).union(set(
                p['dst_ip'] for p in ipsec_packets
            ))),
            'vxlan_vteps': list(set(
                p['src_ip'] for p in vxlan_packets
            ).union(set(
                p['dst_ip'] for p in vxlan_packets
            ))),
            'vxlan_vnis': list(set(p['vni'] for p in vxlan_packets if p['vni']))
        }
        return iocs


### 14.2 Flow Timeline Reconstruction

```python
class FlowTimelineReconstructor:
    """Reconstruct attack flow timeline from multi-source logs"""

    async def reconstruct_attack_flow(
        self,
        incident_id: str,
        data_sources: Dict[str, List[Dict]]
    ) -> Dict[str, Any]:
        """
        Correlate logs from multiple sources to reconstruct attack timeline.

        Args:
            incident_id: Incident ID
            data_sources: {
                'vpc_flow_logs': [...],
                'bgp_logs': [...],
                'firewall_logs': [...],
                'syslog': [...]
            }

        Returns:
            Unified attack flow timeline with correlated events
        """
        unified_timeline = []

        # Normalize all events to common format
        for source_type, events in data_sources.items():
            for event in events:
                unified_event = {
                    'timestamp': self._extract_timestamp(event, source_type),
                    'source_type': source_type,
                    'event_data': event,
                    'severity': self._assess_severity(event, source_type)
                }
                unified_timeline.append(unified_event)

        # Sort chronologically
        unified_timeline.sort(key=lambda x: x['timestamp'])

        # Identify attack phases (reconnaissance, initial access, lateral movement, exfiltration)
        attack_phases = self._identify_attack_phases(unified_timeline)

        # Build attack graph (HopGraph integration)
        attack_graph = await self._build_attack_graph(unified_timeline)

        return {
            'incident_id': incident_id,
            'timeline': unified_timeline,
            'attack_phases': attack_phases,
            'attack_graph': attack_graph,
            'total_events': len(unified_timeline),
            'time_span': {
                'start': unified_timeline[0]['timestamp'] if unified_timeline else None,
                'end': unified_timeline[-1]['timestamp'] if unified_timeline else None
            }
        }

    def _extract_timestamp(self, event: Dict, source_type: str) -> datetime:
        """Extract timestamp from different log formats"""
        if source_type == 'vpc_flow_logs':
            return datetime.fromtimestamp(event.get('start', 0))
        elif source_type == 'bgp_logs':
            return event.get('timestamp', datetime.utcnow())
        elif source_type == 'firewall_logs':
            return datetime.fromisoformat(event.get('timestamp', datetime.utcnow().isoformat()))
        else:
            return datetime.utcnow()

    def _assess_severity(self, event: Dict, source_type: str) -> str:
        """Assess event severity based on content"""
        # Simplified - real implementation would use ML model
        if source_type == 'bgp_logs' and 'hijack' in str(event).lower():
            return 'critical'
        elif source_type == 'firewall_logs' and event.get('action') == 'REJECT':
            return 'high'
        else:
            return 'medium'

    def _identify_attack_phases(self, timeline: List[Dict]) -> Dict[str, List[Dict]]:
        """Map events to MITRE ATT&CK kill chain phases"""
        phases = {
            'reconnaissance': [],
            'initial_access': [],
            'lateral_movement': [],
            'exfiltration': [],
            'impact': []
        }

        for event in timeline:
            # Simplified mapping - real implementation would use MITRE technique mapping
            if event['source_type'] == 'vpc_flow_logs':
                if event['event_data'].get('dest_port') in [22, 3389, 23]:
                    phases['initial_access'].append(event)
                elif event['event_data'].get('bytes_sent', 0) > 100_000_000:
                    phases['exfiltration'].append(event)
            elif event['source_type'] == 'bgp_logs':
                phases['impact'].append(event)

        return phases

    async def _build_attack_graph(self, timeline: List[Dict]) -> Dict[str, Any]:
        """Build HopGraph-compatible attack graph"""
        nodes = []
        edges = []

        for event in timeline:
            if event['source_type'] == 'vpc_flow_logs':
                src = event['event_data'].get('source_ip')
                dst = event['event_data'].get('dest_ip')
                if src and dst:
                    nodes.append({'id': src, 'type': 'ip_address', 'label': src})
                    nodes.append({'id': dst, 'type': 'ip_address', 'label': dst})
                    edges.append({
                        'from': src,
                        'to': dst,
                        'label': f"Port {event['event_data'].get('dest_port')}",
                        'timestamp': event['timestamp'].isoformat()
                    })

        # Deduplicate nodes
        unique_nodes = {node['id']: node for node in nodes}.values()

        return {
            'nodes': list(unique_nodes),
            'edges': edges
        }
```

### 14.3 Chain of Custody Management

```python
class ChainOfCustodyManager:
    """Manage forensic evidence chain of custody"""

    async def transfer_evidence(
        self,
        evidence_id: str,
        from_analyst: str,
        to_analyst: str,
        reason: str
    ) -> bool:
        """
        Transfer evidence between analysts with audit trail.
        """
        # Verify hash before transfer
        evidence = await self._get_evidence(evidence_id)
        current_hash = await self._calculate_hash(evidence.source)

        if current_hash != evidence.hash_sha256:
            # Evidence tampered!
            await self._alert_tampering(evidence_id, from_analyst)
            return False

        # Record transfer
        transfer_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'transferred',
            'from': from_analyst,
            'to': to_analyst,
            'reason': reason,
            'hash_verified': True
        }

        evidence.chain_of_custody.append(transfer_record)
        await self._save_evidence(evidence)

        return True

    async def export_evidence_report(
        self,
        evidence_id: str,
        format: str = 'pdf'
    ) -> bytes:
        """
        Generate chain of custody report for court proceedings.
        """
        evidence = await self._get_evidence(evidence_id)

        report_data = {
            'evidence_id': evidence.evidence_id,
            'incident_id': evidence.incident_id,
            'collection_timestamp': evidence.collection_timestamp.isoformat(),
            'original_hash': evidence.hash_sha256,
            'preservation_method': evidence.preservation_method,
            'chain_of_custody': evidence.chain_of_custody,
            'analysis_notes': evidence.analysis_notes,
            'export_timestamp': datetime.utcnow().isoformat()
        }

        if format == 'pdf':
            return await self._generate_pdf_report(report_data)
        else:
            return json.dumps(report_data, indent=2).encode()
```

---

## 15. CCIE-Level Network Analysis Features

Network engineers with CCIE-level expertise need advanced troubleshooting and analysis tools that go beyond standard monitoring.

### 15.1 BGP Policy Analyzer

```python
"""
ccie_tools.py - Advanced network analysis for CCIE-level engineers
"""
from typing import List, Dict, Optional, Any
from dataclasses import dataclass


@dataclass
class BGPPolicy:
    """BGP routing policy (route-map, AS-PATH filter, community)"""
    policy_name: str
    policy_type: str  # route_map, as_path_filter, community_list, prefix_list
    statements: List[Dict[str, Any]]
    applied_to: List[str]  # Neighbors or peer groups


class BGPPolicyAnalyzer:
    """Analyze BGP policies for misconfigurations and vulnerabilities"""

    async def analyze_route_map(
        self,
        route_map: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze BGP route-map for common issues:
        - Missing deny statements (implicit permit any)
        - Overly permissive AS-PATH filters
        - Community manipulation vulnerabilities
        - MED (metric) manipulation risks
        """
        issues = []

        # Check for implicit permit
        has_explicit_deny = any(
            stmt.get('action') == 'deny'
            for stmt in route_map.get('statements', [])
        )
        if not has_explicit_deny:
            issues.append({
                'severity': 'medium',
                'type': 'missing_deny',
                'description': 'Route-map lacks explicit deny statement, may permit unintended routes',
                'recommendation': 'Add explicit deny statement at end of route-map'
            })

        # Check AS-PATH prepending limits
        for stmt in route_map.get('statements', []):
            if stmt.get('set_as_path_prepend'):
                prepend_count = len(stmt['set_as_path_prepend'])
                if prepend_count > 5:
                    issues.append({
                        'severity': 'low',
                        'type': 'excessive_prepend',
                        'description': f'AS-PATH prepending {prepend_count} times may cause routing instability',
                        'recommendation': 'Limit AS-PATH prepending to 3-5 times'
                    })

        # Check MED manipulation
        for stmt in route_map.get('statements', []):
            if stmt.get('set_med'):
                med_value = stmt['set_med']
                if med_value > 1000:
                    issues.append({
                        'severity': 'medium',
                        'type': 'high_med',
                        'description': f'High MED value ({med_value}) may cause traffic engineering issues',
                        'recommendation': 'Use MED values < 1000 for predictable routing'
                    })

        return {
            'route_map_name': route_map.get('name'),
            'total_statements': len(route_map.get('statements', [])),
            'issues': issues,
            'security_score': self._calculate_security_score(issues)
        }

    def _calculate_security_score(self, issues: List[Dict]) -> int:
        """Calculate security score (0-100)"""
        base_score = 100
        for issue in issues:
            if issue['severity'] == 'critical':
                base_score -= 30
            elif issue['severity'] == 'high':
                base_score -= 20
            elif issue['severity'] == 'medium':
                base_score -= 10
            elif issue['severity'] == 'low':
                base_score -= 5
        return max(base_score, 0)

    async def simulate_route_propagation(
        self,
        prefix: str,
        origin_asn: int,
        topology: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Simulate BGP route propagation through network topology.
        Useful for predicting impact of policy changes.
        """
        # Simplified simulation - real implementation would use graph algorithms
        propagation_path = []
        for peer in topology.get('peers', []):
            propagation_path.append({
                'peer_asn': peer['asn'],
                'peer_ip': peer['ip'],
                'accepted': True,  # Would check against policy
                'as_path': [origin_asn, peer['asn']],
                'local_pref': 100
            })

        return {
            'prefix': prefix,
            'origin_asn': origin_asn,
            'propagation_path': propagation_path,
            'total_peers_reached': len(propagation_path)
        }


### 15.2 OSPF Adjacency Debugger

```python
class OSPFAdjacencyDebugger:
    """Debug OSPF neighbor adjacency issues"""

    async def diagnose_adjacency_failure(
        self,
        local_router: str,
        neighbor_ip: str,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Diagnose why OSPF adjacency is not forming.

        Common issues:
        - MTU mismatch
        - Area mismatch
        - Authentication failure
        - Network type mismatch (broadcast vs point-to-point)
        - Hello/Dead interval mismatch
        """
        diagnosis = {
            'local_router': local_router,
            'neighbor_ip': neighbor_ip,
            'root_causes': [],
            'recommendations': []
        }

        # Check for MTU mismatch
        mtu_mismatches = [
            log for log in logs
            if 'mtu mismatch' in log.get('message', '').lower()
        ]
        if mtu_mismatches:
            diagnosis['root_causes'].append({
                'issue': 'MTU Mismatch',
                'description': 'OSPF DBD packets failing due to MTU size difference',
                'evidence': mtu_mismatches[0]
            })
            diagnosis['recommendations'].append(
                'Verify interface MTU matches on both sides (show ip ospf interface)'
            )

        # Check for area mismatch
        area_mismatches = [
            log for log in logs
            if 'area mismatch' in log.get('message', '').lower()
        ]
        if area_mismatches:
            diagnosis['root_causes'].append({
                'issue': 'Area Mismatch',
                'description': 'Neighbors configured in different OSPF areas',
                'evidence': area_mismatches[0]
            })
            diagnosis['recommendations'].append(
                'Configure both routers in same OSPF area'
            )

        # Check for authentication failure
        auth_failures = [
            log for log in logs
            if 'authentication' in log.get('message', '').lower()
        ]
        if auth_failures:
            diagnosis['root_causes'].append({
                'issue': 'Authentication Failure',
                'description': 'OSPF authentication keys do not match',
                'evidence': auth_failures[0]
            })
            diagnosis['recommendations'].append(
                'Verify OSPF authentication type and keys match on both sides'
            )

        # Check for Hello/Dead interval mismatch
        timer_mismatches = [
            log for log in logs
            if 'hello' in log.get('message', '').lower() or 'dead' in log.get('message', '').lower()
        ]
        if timer_mismatches:
            diagnosis['root_causes'].append({
                'issue': 'Timer Mismatch',
                'description': 'Hello or Dead interval timers do not match',
                'evidence': timer_mismatches[0]
            })
            diagnosis['recommendations'].append(
                'Verify ip ospf hello-interval and ip ospf dead-interval match'
            )

        return diagnosis

    async def analyze_lsa_database(
        self,
        lsa_database: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze OSPF LSA database for anomalies:
        - Duplicate router IDs
        - Excessive LSA flooding
        - Stale LSAs (age = 3600)
        - Type-5 LSA abuse (route injection)
        """
        analysis = {
            'total_lsas': len(lsa_database),
            'lsa_types': {},
            'anomalies': []
        }

        # Count LSA types
        for lsa in lsa_database:
            lsa_type = lsa.get('type')
            analysis['lsa_types'][lsa_type] = analysis['lsa_types'].get(lsa_type, 0) + 1

        # Check for duplicate router IDs
        router_ids = [lsa.get('advertising_router') for lsa in lsa_database if lsa.get('type') == 'router']
        duplicates = [rid for rid in set(router_ids) if router_ids.count(rid) > 1]
        if duplicates:
            analysis['anomalies'].append({
                'type': 'duplicate_router_id',
                'description': f'Duplicate router IDs detected: {duplicates}',
                'severity': 'critical'
            })

        # Check for stale LSAs
        stale_lsas = [lsa for lsa in lsa_database if lsa.get('age', 0) >= 3600]
        if stale_lsas:
            analysis['anomalies'].append({
                'type': 'stale_lsa',
                'description': f'{len(stale_lsas)} LSAs at max age (3600 seconds)',
                'severity': 'high'
            })

        # Check for excessive Type-5 LSAs (potential route injection attack)
        type5_count = analysis['lsa_types'].get('external', 0)
        if type5_count > 1000:
            analysis['anomalies'].append({
                'type': 'excessive_type5',
                'description': f'Excessive Type-5 External LSAs ({type5_count})',
                'severity': 'high'
            })

        return analysis


### 15.3 IPsec Phase 1/Phase 2 Diagnostic Tool

```python
class IPsecDiagnosticTool:
    """Diagnose IPsec VPN tunnel issues"""

    async def diagnose_phase1_failure(
        self,
        tunnel_id: str,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Diagnose IKEv2 Phase 1 (Main Mode / Aggressive Mode) failures.

        Common issues:
        - Pre-shared key mismatch
        - Encryption algorithm mismatch (AES-256 vs AES-128)
        - Diffie-Hellman group mismatch (Group 2 vs Group 14)
        - Lifetime mismatch
        - NAT-T issues
        """
        diagnosis = {
            'tunnel_id': tunnel_id,
            'phase': 'Phase 1 (IKE)',
            'root_causes': [],
            'recommendations': []
        }

        # Check for PSK mismatch
        psk_failures = [
            log for log in logs
            if 'pre-shared key' in log.get('message', '').lower() or 'authentication failed' in log.get('message', '').lower()
        ]
        if psk_failures:
            diagnosis['root_causes'].append({
                'issue': 'Pre-Shared Key Mismatch',
                'description': 'IKE authentication failing due to PSK mismatch',
                'evidence': psk_failures[0]
            })
            diagnosis['recommendations'].append(
                'Verify crypto isakmp key matches on both peers'
            )

        # Check for encryption mismatch
        crypto_failures = [
            log for log in logs
            if 'no proposal chosen' in log.get('message', '').lower()
        ]
        if crypto_failures:
            diagnosis['root_causes'].append({
                'issue': 'Encryption/Hash Mismatch',
                'description': 'Phase 1 proposal mismatch (encryption, hash, DH group)',
                'evidence': crypto_failures[0]
            })
            diagnosis['recommendations'].append(
                'Verify Phase 1 policy: encryption (aes 256), hash (sha256), group (14)'
            )

        # Check for NAT-T issues
        nat_issues = [
            log for log in logs
            if 'nat-t' in log.get('message', '').lower()
        ]
        if nat_issues:
            diagnosis['root_causes'].append({
                'issue': 'NAT Traversal Issue',
                'description': 'NAT-T negotiation failing or UDP 4500 blocked',
                'evidence': nat_issues[0]
            })
            diagnosis['recommendations'].append(
                'Ensure UDP 500 and UDP 4500 allowed through firewall for NAT-T'
            )

        return diagnosis

    async def diagnose_phase2_failure(
        self,
        tunnel_id: str,
        logs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Diagnose IPsec Phase 2 (Quick Mode) failures.

        Common issues:
        - Transform set mismatch (ESP-AES vs ESP-3DES)
        - PFS group mismatch
        - Lifetime mismatch
        - Proxy ID / Interesting traffic mismatch
        """
        diagnosis = {
            'tunnel_id': tunnel_id,
            'phase': 'Phase 2 (IPsec)',
            'root_causes': [],
            'recommendations': []
        }

        # Check for transform set mismatch
        transform_failures = [
            log for log in logs
            if 'invalid proposal' in log.get('message', '').lower()
        ]
        if transform_failures:
            diagnosis['root_causes'].append({
                'issue': 'Transform Set Mismatch',
                'description': 'Phase 2 transform set mismatch (ESP-AES, ESP-SHA-HMAC)',
                'evidence': transform_failures[0]
            })
            diagnosis['recommendations'].append(
                'Verify crypto ipsec transform-set matches on both peers'
            )

        # Check for PFS mismatch
        pfs_failures = [
            log for log in logs
            if 'pfs' in log.get('message', '').lower()
        ]
        if pfs_failures:
            diagnosis['root_causes'].append({
                'issue': 'PFS Group Mismatch',
                'description': 'Perfect Forward Secrecy (PFS) DH group mismatch',
                'evidence': pfs_failures[0]
            })
            diagnosis['recommendations'].append(
                'Verify PFS group matches (set pfs group14)'
            )

        # Check for proxy ID mismatch
        proxy_failures = [
            log for log in logs
            if 'proxy' in log.get('message', '').lower() or 'interesting traffic' in log.get('message', '').lower()
        ]
        if proxy_failures:
            diagnosis['root_causes'].append({
                'issue': 'Proxy ID Mismatch',
                'description': 'Interesting traffic selectors do not match (crypto map ACL)',
                'evidence': proxy_failures[0]
            })
            diagnosis['recommendations'].append(
                'Verify crypto ACL matches on both peers (show crypto map)'
            )

        return diagnosis


### 15.4 VXLAN Encapsulation Troubleshooter

```python
class VXLANTroubleshooter:
    """Troubleshoot VXLAN overlay network issues"""

    async def diagnose_vxlan_issue(
        self,
        vni: int,
        symptoms: List[str]
    ) -> Dict[str, Any]:
        """
        Diagnose VXLAN issues:
        - VTEP reachability failure
        - MAC learning issues
        - VNI mapping errors
        - MTU issues (jumbo frames required for VXLAN overhead)
        - Multicast group issues (for BUM traffic)
        """
        diagnosis = {
            'vni': vni,
            'symptoms': symptoms,
            'root_causes': [],
            'recommendations': []
        }

        # Check for VTEP reachability
        if 'no connectivity' in ' '.join(symptoms).lower():
            diagnosis['root_causes'].append({
                'issue': 'VTEP Unreachable',
                'description': 'VXLAN Tunnel Endpoint (VTEP) not reachable via underlay',
                'tests': [
                    'Ping remote VTEP IP',
                    'Verify NVE interface up (show nve peers)',
                    'Check BGP EVPN routes (show bgp l2vpn evpn)'
                ]
            })
            diagnosis['recommendations'].append(
                'Verify underlay routing (OSPF/BGP) and VTEP IP reachability'
            )

        # Check for MAC learning issues
        if 'mac not learning' in ' '.join(symptoms).lower():
            diagnosis['root_causes'].append({
                'issue': 'MAC Learning Failure',
                'description': 'MAC addresses not learning in VXLAN segment',
                'tests': [
                    'show mac address-table vlan <VNI>',
                    'show nve mac',
                    'debug nve packet'
                ]
            })
            diagnosis['recommendations'].append(
                'Verify ARP suppression config and EVPN control plane'
            )

        # Check for MTU issues
        if 'fragmentation' in ' '.join(symptoms).lower() or 'mtu' in ' '.join(symptoms).lower():
            diagnosis['root_causes'].append({
                'issue': 'MTU Mismatch',
                'description': 'VXLAN requires 50-byte overhead, may cause fragmentation',
                'tests': [
                    'Verify underlay MTU: show interface <interface> | include MTU',
                    'Expected: 9000 bytes for jumbo frames, 1550+ for standard'
                ]
            })
            diagnosis['recommendations'].append(
                'Increase underlay MTU to at least 1550 bytes (1500 + 50 VXLAN overhead)'
            )

        # Check for multicast issues (traditional VXLAN flood-and-learn)
        if 'bum traffic not working' in ' '.join(symptoms).lower():
            diagnosis['root_causes'].append({
                'issue': 'Multicast Group Issue',
                'description': 'BUM (Broadcast, Unknown unicast, Multicast) traffic not flooding',
                'tests': [
                    'show ip pim neighbor',
                    'show ip mroute <multicast-group>',
                    'show nve vni <VNI>'
                ]
            })
            diagnosis['recommendations'].append(
                'Verify PIM multicast routing or use ingress replication instead'
            )

        return diagnosis

    async def analyze_vxlan_overhead(
        self,
        original_packet_size: int
    ) -> Dict[str, Any]:
        """
        Calculate VXLAN encapsulation overhead.

        VXLAN overhead:
        - Outer Ethernet: 14 bytes
        - Outer IP: 20 bytes (IPv4) or 40 bytes (IPv6)
        - Outer UDP: 8 bytes
        - VXLAN header: 8 bytes
        Total: 50 bytes (IPv4) or 70 bytes (IPv6)
        """
        ipv4_overhead = 14 + 20 + 8 + 8  # 50 bytes
        ipv6_overhead = 14 + 40 + 8 + 8  # 70 bytes

        encapsulated_ipv4 = original_packet_size + ipv4_overhead
        encapsulated_ipv6 = original_packet_size + ipv6_overhead

        return {
            'original_packet_size': original_packet_size,
            'vxlan_ipv4': {
                'total_size': encapsulated_ipv4,
                'overhead': ipv4_overhead,
                'overhead_percentage': (ipv4_overhead / encapsulated_ipv4) * 100
            },
            'vxlan_ipv6': {
                'total_size': encapsulated_ipv6,
                'overhead': ipv6_overhead,
                'overhead_percentage': (ipv6_overhead / encapsulated_ipv6) * 100
            },
            'mtu_recommendation': max(encapsulated_ipv4, encapsulated_ipv6)
        }


### 15.5 Network Latency Analyzer

```python
class NetworkLatencyAnalyzer:
    """Analyze network latency for performance troubleshooting"""

    async def measure_hop_latency(
        self,
        source: str,
        destination: str
    ) -> Dict[str, Any]:
        """
        Measure per-hop latency using traceroute with timestamps.
        """
        # Simplified - real implementation would use scapy or system traceroute
        hops = [
            {'hop': 1, 'ip': '10.0.1.1', 'latency_ms': 1.2},
            {'hop': 2, 'ip': '192.168.1.1', 'latency_ms': 5.8},
            {'hop': 3, 'ip': destination, 'latency_ms': 12.4}
        ]

        total_latency = sum(hop['latency_ms'] for hop in hops)

        # Identify high-latency hops
        high_latency_hops = [
            hop for hop in hops
            if hop['latency_ms'] > 10.0
        ]

        return {
            'source': source,
            'destination': destination,
            'total_hops': len(hops),
            'total_latency_ms': total_latency,
            'hops': hops,
            'high_latency_hops': high_latency_hops
        }

    async def analyze_jitter(
        self,
        latency_samples: List[float]
    ) -> Dict[str, Any]:
        """
        Analyze network jitter (latency variation).
        Critical for VoIP and real-time applications.
        """
        if not latency_samples:
            return {}

        avg_latency = sum(latency_samples) / len(latency_samples)
        min_latency = min(latency_samples)
        max_latency = max(latency_samples)
        jitter = max_latency - min_latency

        # Calculate standard deviation
        variance = sum((x - avg_latency) ** 2 for x in latency_samples) / len(latency_samples)
        std_dev = variance ** 0.5

        # Assess quality
        if jitter < 10:
            quality = 'excellent'
        elif jitter < 30:
            quality = 'good'
        elif jitter < 50:
            quality = 'acceptable'
        else:
            quality = 'poor'

        return {
            'avg_latency_ms': round(avg_latency, 2),
            'min_latency_ms': round(min_latency, 2),
            'max_latency_ms': round(max_latency, 2),
            'jitter_ms': round(jitter, 2),
            'std_dev_ms': round(std_dev, 2),
            'quality': quality,
            'samples': len(latency_samples)
        }
```

---

## 16. CSV UI Enhancements for Network Analysis

When analysts upload network flow logs via CSV, the UI needs to display network-specific enrichments and provide quick investigation tools.

### 16.1 Changes to `csv_deep_analyze.html`

**New Network Flow Columns:**

```html
<!-- Add after existing CSV table in csv_deep_analyze.html -->
<div class="csv-table-container">
  <table id="csvNetworkTable" class="csv-table">
    <thead>
      <tr>
        <th>Row</th>
        <th>Timestamp</th>
        <th>Source IP</th>
        <th>Source Port</th>
        <th>Dest IP</th>
        <th>Dest Port</th>
        <th>Protocol</th>
        <th>Bytes</th>
        <th>Action</th>

        <!-- Network Enrichments -->
        <th>Source ASN</th>
        <th>Source Country</th>
        <th>Dest ASN</th>
        <th>Dest Country</th>
        <th>Port Risk</th>
        <th>Threat Intel</th>
        <th>RPKI Status</th>

        <!-- Actions -->
        <th>Actions</th>
      </tr>
    </thead>
    <tbody id="csvNetworkBody">
      <!-- Populated by JavaScript -->
    </tbody>
  </table>
</div>

<style>
/* Risk-based row highlighting */
tr.risk-critical {
  background-color: #ffcccc !important;
  border-left: 4px solid #d9534f;
}

tr.risk-high {
  background-color: #ffe6cc !important;
  border-left: 4px solid #f0ad4e;
}

tr.risk-medium {
  background-color: #fff9cc !important;
  border-left: 4px solid #f0ad4e;
}

tr.risk-low {
  background-color: #e6f7ff;
  border-left: 4px solid #5bc0de;
}

/* Port risk badges */
.port-risk-badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: bold;
}

.port-risk-critical {
  background-color: #d9534f;
  color: white;
}

.port-risk-high {
  background-color: #f0ad4e;
  color: white;
}

.port-risk-medium {
  background-color: #f0ad4e;
  color: #333;
}

.port-risk-low {
  background-color: #5cb85c;
  color: white;
}

/* RPKI status badges */
.rpki-valid {
  background-color: #5cb85c;
  color: white;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
}

.rpki-invalid {
  background-color: #d9534f;
  color: white;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
}

.rpki-unknown {
  background-color: #999;
  color: white;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
}
</style>

<script>
// Render network flow rows with enrichments
async function renderNetworkFlowRow(row, enrichments, rowIndex) {
  const tr = document.createElement('tr');

  // Apply risk-based highlighting
  const overallRisk = calculateOverallRisk(row, enrichments);
  tr.className = `risk-${overallRisk}`;

  tr.innerHTML = `
    <td>${rowIndex + 1}</td>
    <td>${row.timestamp}</td>
    <td>
      ${row.source_ip}
      <button class="btn-icon" onclick="investigateIP('${row.source_ip}')" title="Investigate IP">
        🔍
      </button>
    </td>
    <td>${row.source_port}</td>
    <td>
      ${row.dest_ip}
      <button class="btn-icon" onclick="investigateIP('${row.dest_ip}')" title="Investigate IP">
        🔍
      </button>
    </td>
    <td>${row.dest_port}</td>
    <td>${row.protocol}</td>
    <td>${formatBytes(row.bytes)}</td>
    <td>
      <span class="action-badge action-${row.action.toLowerCase()}">
        ${row.action}
      </span>
    </td>

    <!-- Enrichments -->
    <td>
      ${enrichments.source_asn || 'N/A'}
      ${enrichments.source_asn ? `<button class="btn-icon" onclick="lookupASN(${enrichments.source_asn})" title="ASN Info">ℹ️</button>` : ''}
    </td>
    <td>
      ${enrichments.geo_source?.country || 'N/A'}
      <span class="flag-icon">${getCountryFlag(enrichments.geo_source?.country)}</span>
    </td>
    <td>${enrichments.dest_asn || 'N/A'}</td>
    <td>
      ${enrichments.geo_dest?.country || 'N/A'}
      <span class="flag-icon">${getCountryFlag(enrichments.geo_dest?.country)}</span>
    </td>
    <td>
      <span class="port-risk-badge port-risk-${enrichments.port_classification?.risk_level?.toLowerCase()}">
        ${enrichments.port_classification?.risk_level || 'LOW'}
      </span>
      <br>
      <small>${enrichments.port_classification?.service || ''}</small>
    </td>
    <td>
      ${renderThreatIntel(enrichments.threat_intel)}
    </td>
    <td>
      ${enrichments.rpki_validation ? `<span class="rpki-${enrichments.rpki_validation.status}">${enrichments.rpki_validation.status.toUpperCase()}</span>` : 'N/A'}
    </td>

    <!-- Actions -->
    <td>
      <button class="btn-sm" onclick="runPlaybook('investigate_flow', ${rowIndex})">
        📋 Playbook
      </button>
      <button class="btn-sm" onclick="addToHopGraph(${rowIndex})">
        🕸️ Add to Graph
      </button>
    </td>
  `;

  return tr;
}

function calculateOverallRisk(row, enrichments) {
  // Risk scoring logic
  let riskScore = 0;

  // Port risk
  if (enrichments.port_classification?.risk_level === 'CRITICAL') riskScore += 40;
  else if (enrichments.port_classification?.risk_level === 'HIGH') riskScore += 30;
  else if (enrichments.port_classification?.risk_level === 'MEDIUM') riskScore += 15;

  // Threat intel
  if (enrichments.threat_intel?.reputation === 'malicious') riskScore += 50;
  else if (enrichments.threat_intel?.reputation === 'suspicious') riskScore += 25;

  // RPKI
  if (enrichments.rpki_validation?.status === 'invalid') riskScore += 30;

  // Action
  if (row.action === 'REJECT') riskScore += 10;

  // Bytes (large exfiltration)
  if (row.bytes > 100_000_000) riskScore += 20;

  // Final classification
  if (riskScore >= 70) return 'critical';
  if (riskScore >= 50) return 'high';
  if (riskScore >= 30) return 'medium';
  return 'low';
}

function renderThreatIntel(threatIntel) {
  if (!threatIntel) return 'N/A';

  const { reputation, categories } = threatIntel;
  let html = `<span class="threat-badge threat-${reputation}">${reputation}</span>`;

  if (categories && categories.length > 0) {
    html += `<br><small>${categories.join(', ')}</small>`;
  }

  return html;
}

// Investigation actions
async function investigateIP(ip) {
  // Open investigation modal with WHOIS, RPKI, BGPmon, ASN lookup
  const modal = document.getElementById('investigationModal');
  const content = document.getElementById('investigationContent');

  content.innerHTML = `<div class="loading">Loading IP investigation for ${ip}...</div>`;
  modal.style.display = 'block';

  // Fetch investigation data
  const [whois, asn, threatIntel, bgpHistory] = await Promise.all([
    fetch(`/api/v1/network/whois?ip=${ip}`).then(r => r.json()),
    fetch(`/api/v1/network/asn-lookup?ip=${ip}`).then(r => r.json()),
    fetch(`/api/v1/network/threat-intel?ip=${ip}`).then(r => r.json()),
    fetch(`/api/v1/network/bgp-history?ip=${ip}`).then(r => r.json())
  ]);

  content.innerHTML = `
    <h3>🔍 IP Investigation: ${ip}</h3>

    <div class="info-section">
      <h4>📋 WHOIS Information</h4>
      <pre>${JSON.stringify(whois, null, 2)}</pre>
    </div>

    <div class="info-section">
      <h4>🏢 ASN Information</h4>
      <pre>${JSON.stringify(asn, null, 2)}</pre>
    </div>

    <div class="info-section">
      <h4>🚨 Threat Intelligence</h4>
      <pre>${JSON.stringify(threatIntel, null, 2)}</pre>
    </div>

    <div class="info-section">
      <h4>📡 BGP History (24h)</h4>
      <pre>${JSON.stringify(bgpHistory, null, 2)}</pre>
    </div>

    <button onclick="closeModal()">Close</button>
  `;
}

async function lookupASN(asn) {
  // Open ASN details modal
  const modal = document.getElementById('asnModal');
  const content = document.getElementById('asnContent');

  content.innerHTML = `<div class="loading">Loading ASN ${asn} information...</div>`;
  modal.style.display = 'block';

  const [asnInfo, peeringDB] = await Promise.all([
    fetch(`/api/v1/network/asn/${asn}`).then(r => r.json()),
    fetch(`/api/v1/network/peeringdb/${asn}`).then(r => r.json())
  ]);

  content.innerHTML = `
    <h3>🏢 AS${asn} Information</h3>

    <div class="info-section">
      <h4>Organization</h4>
      <p><strong>Name:</strong> ${asnInfo.org_name}</p>
      <p><strong>Country:</strong> ${asnInfo.country}</p>
      <p><strong>Prefixes Announced:</strong> ${asnInfo.prefixes_count}</p>
    </div>

    <div class="info-section">
      <h4>🤝 PeeringDB Info</h4>
      <p><strong>IXPs:</strong> ${peeringDB.ixps.join(', ')}</p>
      <p><strong>NOC Contact:</strong> ${peeringDB.noc_email}</p>
    </div>

    <button onclick="closeModal()">Close</button>
  `;
}

async function runPlaybook(playbookId, rowIndex) {
  // Execute network investigation playbook
  const row = csvData[rowIndex];

  const response = await fetch('/api/v1/playbooks/execute', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      playbook_id: playbookId,
      context: {
        row_index: rowIndex,
        source_ip: row.source_ip,
        dest_ip: row.dest_ip,
        dest_port: row.dest_port,
        protocol: row.protocol
      }
    })
  });

  const result = await response.json();

  // Show playbook results
  alert(`Playbook "${playbookId}" executed. Results: ${JSON.stringify(result)}`);
}

async function addToHopGraph(rowIndex) {
  // Add flow to HopGraph visualization
  const row = csvData[rowIndex];

  await fetch('/api/v1/hopgraph/add-node', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      nodes: [
        { id: row.source_ip, type: 'ip_address', label: row.source_ip },
        { id: row.dest_ip, type: 'ip_address', label: row.dest_ip }
      ],
      edges: [
        {
          from: row.source_ip,
          to: row.dest_ip,
          label: `${row.protocol}:${row.dest_port}`,
          timestamp: row.timestamp
        }
      ]
    })
  });

  alert(`Added flow to HopGraph. View at /static/attack_graph.html`);
}
</script>
```

### 16.2 Changes to `csv_analyze.html`

**Add Network Detection Summary Panel:**

```html
<!-- Add after existing summary cards in csv_analyze.html -->
<div class="summary-panel">
  <div class="summary-card">
    <h3>🌐 Network Summary</h3>
    <div id="networkSummary">
      <p><strong>Total Flows:</strong> <span id="totalFlows">0</span></p>
      <p><strong>Unique Source IPs:</strong> <span id="uniqueSources">0</span></p>
      <p><strong>Unique Dest IPs:</strong> <span id="uniqueDests">0</span></p>
      <p><strong>Total Data Transferred:</strong> <span id="totalBytes">0 MB</span></p>
      <p><strong>Top Protocol:</strong> <span id="topProtocol">N/A</span></p>
    </div>
  </div>

  <div class="summary-card">
    <h3>🚨 Network Anomalies</h3>
    <div id="networkAnomalies">
      <div class="anomaly-item">
        <span class="anomaly-badge anomaly-critical">BGP Hijacks:</span>
        <span id="bgpHijacks">0</span>
      </div>
      <div class="anomaly-item">
        <span class="anomaly-badge anomaly-high">Route Leaks:</span>
        <span id="routeLeaks">0</span>
      </div>
      <div class="anomaly-item">
        <span class="anomaly-badge anomaly-high">IPsec Downgrades:</span>
        <span id="ipsecDowngrades">0</span>
      </div>
      <div class="anomaly-item">
        <span class="anomaly-badge anomaly-medium">VXLAN Anomalies:</span>
        <span id="vxlanAnomalies">0</span>
      </div>
      <div class="anomaly-item">
        <span class="anomaly-badge anomaly-low">Port Scans:</span>
        <span id="portScans">0</span>
      </div>
    </div>
  </div>

  <div class="summary-card">
    <h3>🌍 Geographic Distribution</h3>
    <div id="geoChart">
      <!-- D3.js world map showing source/dest countries -->
    </div>
  </div>

  <div class="summary-card">
    <h3>🏢 Top ASNs</h3>
    <div id="topASNs">
      <ol id="asnList">
        <!-- Populated by JavaScript -->
      </ol>
    </div>
  </div>
</div>

<script>
async function generateNetworkSummary(csvData) {
  // Calculate network statistics
  const totalFlows = csvData.length;
  const uniqueSources = new Set(csvData.map(r => r.source_ip)).size;
  const uniqueDests = new Set(csvData.map(r => r.dest_ip)).size;
  const totalBytes = csvData.reduce((sum, r) => sum + (r.bytes || 0), 0);

  // Protocol distribution
  const protocolCounts = {};
  csvData.forEach(r => {
    protocolCounts[r.protocol] = (protocolCounts[r.protocol] || 0) + 1;
  });
  const topProtocol = Object.keys(protocolCounts).reduce((a, b) =>
    protocolCounts[a] > protocolCounts[b] ? a : b
  );

  // Update UI
  document.getElementById('totalFlows').textContent = totalFlows.toLocaleString();
  document.getElementById('uniqueSources').textContent = uniqueSources.toLocaleString();
  document.getElementById('uniqueDests').textContent = uniqueDests.toLocaleString();
  document.getElementById('totalBytes').textContent = (totalBytes / 1024 / 1024).toFixed(2) + ' MB';
  document.getElementById('topProtocol').textContent = topProtocol;

  // Fetch anomaly counts from backend
  const anomalies = await fetch('/api/v1/network/analyze-anomalies', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ flows: csvData })
  }).then(r => r.json());

  document.getElementById('bgpHijacks').textContent = anomalies.bgp_hijacks || 0;
  document.getElementById('routeLeaks').textContent = anomalies.route_leaks || 0;
  document.getElementById('ipsecDowngrades').textContent = anomalies.ipsec_downgrades || 0;
  document.getElementById('vxlanAnomalies').textContent = anomalies.vxlan_anomalies || 0;
  document.getElementById('portScans').textContent = anomalies.port_scans || 0;
}
</script>
```

---

## 17. Playbook Integration for Network Security

Network-specific playbooks automate investigation and response workflows.

### 17.1 BGP Hijack Response Playbook

```python
"""
network_playbooks.py - Automated network security playbooks
"""
from typing import Dict, List, Any
from datetime import datetime


class NetworkPlaybookExecutor:
    """Execute network security investigation playbooks"""

    async def execute_bgp_hijack_response(
        self,
        incident_id: str,
        hijacked_prefix: str,
        rogue_asn: int
    ) -> Dict[str, Any]:
        """
        BGP Hijack Response Playbook:

        1. Verify hijack via RPKI
        2. Query BGPmon for propagation scope
        3. Contact legitimate prefix owner
        4. Generate ROA (Route Origin Authorization) if missing
        5. Notify ISP abuse contacts
        6. Document incident timeline
        """
        playbook_run = {
            'playbook_id': 'bgp_hijack_response',
            'incident_id': incident_id,
            'start_time': datetime.utcnow(),
            'steps': [],
            'status': 'running'
        }

        # Step 1: Verify via RPKI
        rpki_result = await self._verify_rpki(hijacked_prefix, rogue_asn)
        playbook_run['steps'].append({
            'step': 1,
            'action': 'RPKI Validation',
            'result': rpki_result,
            'status': 'completed'
        })

        # Step 2: Query BGPmon
        bgpmon_result = await self._query_bgpmon(hijacked_prefix)
        playbook_run['steps'].append({
            'step': 2,
            'action': 'BGPmon Propagation Check',
            'result': bgpmon_result,
            'status': 'completed'
        })

        # Step 3: Lookup legitimate owner
        whois_result = await self._whois_lookup(hijacked_prefix)
        playbook_run['steps'].append({
            'step': 3,
            'action': 'WHOIS Lookup',
            'result': whois_result,
            'status': 'completed'
        })

        # Step 4: Check ROA existence
        roa_check = await self._check_roa(hijacked_prefix)
        if not roa_check['exists']:
            playbook_run['steps'].append({
                'step': 4,
                'action': 'ROA Missing',
                'result': 'Recommend creating ROA for prefix',
                'status': 'action_required'
            })

        # Step 5: Notify abuse contacts
        notifications = await self._notify_abuse_contacts(rogue_asn, incident_id)
        playbook_run['steps'].append({
            'step': 5,
            'action': 'Abuse Contact Notification',
            'result': notifications,
            'status': 'completed'
        })

        # Step 6: Generate incident report
        report = await self._generate_incident_report(playbook_run)
        playbook_run['steps'].append({
            'step': 6,
            'action': 'Incident Report Generated',
            'result': {'report_id': report['id'], 'report_url': report['url']},
            'status': 'completed'
        })

        playbook_run['end_time'] = datetime.utcnow()
        playbook_run['status'] = 'completed'

        return playbook_run


### 17.2 Route Leak Containment Playbook

```python
async def execute_route_leak_containment(
    self,
    incident_id: str,
    leaked_prefixes: List[str],
    leaking_asn: int
) -> Dict[str, Any]:
    """
    Route Leak Containment Playbook:

    1. Identify scope (internal vs external leak)
    2. Generate BGP policy to filter leaked routes
    3. Contact upstream providers to implement filters
    4. Monitor BGP table for leak propagation
    5. Post-incident: implement route validation
    """
    playbook_run = {
        'playbook_id': 'route_leak_containment',
        'incident_id': incident_id,
        'start_time': datetime.utcnow(),
        'steps': []
    }

    # Step 1: Scope analysis
    scope = await self._analyze_leak_scope(leaked_prefixes, leaking_asn)
    playbook_run['steps'].append({
        'step': 1,
        'action': 'Leak Scope Analysis',
        'result': scope,
        'status': 'completed'
    })

    # Step 2: Generate filter policy
    filter_policy = await self._generate_bgp_filter(leaked_prefixes)
    playbook_run['steps'].append({
        'step': 2,
        'action': 'BGP Filter Generation',
        'result': {
            'filter_config': filter_policy,
            'apply_to': 'All BGP peers'
        },
        'status': 'completed'
    })

    # Step 3: Notify upstream providers
    notifications = await self._notify_upstream_providers(leaking_asn, filter_policy)
    playbook_run['steps'].append({
        'step': 3,
        'action': 'Upstream Provider Notification',
        'result': notifications,
        'status': 'completed'
    })

    # Step 4: Monitor BGP table
    monitoring = await self._monitor_bgp_propagation(leaked_prefixes, duration_minutes=30)
    playbook_run['steps'].append({
        'step': 4,
        'action': 'BGP Table Monitoring',
        'result': monitoring,
        'status': 'in_progress'
    })

    return playbook_run


### 17.3 IPsec Hardening Playbook

```python
async def execute_ipsec_hardening(
    self,
    tunnel_id: str,
    detected_weakness: str
) -> Dict[str, Any]:
    """
    IPsec Hardening Playbook:

    1. Audit current IPsec config
    2. Recommend crypto upgrades (AES-256, SHA-256, DH Group 14+)
    3. Generate hardened config template
    4. Test crypto changes in lab environment
    5. Schedule production rollout
    """
    playbook_run = {
        'playbook_id': 'ipsec_hardening',
        'tunnel_id': tunnel_id,
        'detected_weakness': detected_weakness,
        'start_time': datetime.utcnow(),
        'steps': []
    }

    # Step 1: Audit current config
    current_config = await self._audit_ipsec_config(tunnel_id)
    playbook_run['steps'].append({
        'step': 1,
        'action': 'IPsec Configuration Audit',
        'result': current_config,
        'status': 'completed'
    })

    # Step 2: Recommend upgrades
    recommendations = await self._generate_ipsec_recommendations(current_config)
    playbook_run['steps'].append({
        'step': 2,
        'action': 'Crypto Upgrade Recommendations',
        'result': recommendations,
        'status': 'completed'
    })

    # Step 3: Generate hardened config
    hardened_config = await self._generate_hardened_ipsec_config(recommendations)
    playbook_run['steps'].append({
        'step': 3,
        'action': 'Hardened Configuration Generated',
        'result': {
            'config': hardened_config,
            'improvements': [
                'Phase 1: AES-256-CBC, SHA-256, DH Group 14',
                'Phase 2: ESP-AES-256, ESP-SHA-256-HMAC',
                'PFS: Enabled with Group 14',
                'Lifetime: 3600s (reduced from 86400s)'
            ]
        },
        'status': 'completed'
    })

    # Step 4: Lab testing instructions
    playbook_run['steps'].append({
        'step': 4,
        'action': 'Lab Testing Required',
        'result': 'Test hardened config in lab before production rollout',
        'status': 'pending'
    })

    return playbook_run
```

---

## 18. SWOT Analysis: JanuSec Platform with Network Infrastructure Security

### Strengths

1. **Unique Market Position**
   - **Only platform** correlating network infrastructure (BGP, OSPF, IPsec, VXLAN) with endpoint + cloud security
   - Competitors focus on either network OR endpoint, not both
   - HopGraph provides attack path visualization across network + endpoint domains

2. **Cloud-Agnostic Multi-Cloud Support**
   - Unified normalization layer (`UnifiedNetworkFlow`) for AWS, Azure, GCP, Oracle, VMware, OpenStack
   - Plugin-based connector architecture allows easy addition of new cloud providers
   - No vendor lock-in - works with any cloud or private datacenter

3. **Cost-Optimized AI Triage**
   - Gated LLM summaries prevent wasteful spending on low-signal events
   - Tier 1 (fast triage) → Tier 2 (deep investigation) escalation model
   - Human-in-the-loop gates ensure LLM costs only for high-value analysis
   - Example: 5 trigger gates reduce LLM cost by 70-80% vs. analyzing every flow

4. **CCIE-Level Network Analysis Tools**
   - BGP policy analyzer (route-map security audits, AS-PATH validation)
   - OSPF adjacency debugger (MTU, area, auth mismatch diagnosis)
   - IPsec Phase 1/2 diagnostic tools (crypto mismatch, NAT-T, PFS debugging)
   - VXLAN troubleshooter (VTEP reachability, MAC learning, MTU overhead)
   - Network latency/jitter analyzer

5. **Network Forensics Capabilities**
   - PCAP analysis for BGP/IPsec/VXLAN packet inspection
   - Chain of custody management for network evidence
   - Attack timeline reconstruction from multi-source logs
   - HopGraph integration for visual attack flow correlation

6. **Pre-Built Hunt Queries**
   - 5+ ready-to-use threat hunting queries (BGP hijack campaigns, VPN downgrades, VXLAN bypass, lateral movement, DNS tunneling)
   - Custom hunt builder for network-specific investigations
   - Threat hunting focuses on infrastructure-layer attacks (missing in EDR/SIEM)

7. **Playbook Automation**
   - BGP hijack response (RPKI validation, BGPmon, ROA generation, abuse notification)
   - Route leak containment (scope analysis, filter generation, upstream notification)
   - IPsec hardening (crypto audit, upgrade recommendations, config generation)
   - VXLAN segmentation enforcement

8. **Persona-Based Reporting**
   - Network engineer reports (CCIE-level troubleshooting steps, CLI commands)
   - SOC analyst reports (triage summaries, investigation playbooks)
   - Executive reports (business impact, compliance risk)
   - Forensic analyst reports (chain of custody, evidence timeline)

9. **Comprehensive CSV Analysis UI**
   - Risk-based row highlighting (critical/high/medium/low)
   - Inline network enrichments (ASN, Geo, RPKI, threat intel, port risk)
   - One-click investigation tools (WHOIS, BGPmon, PeeringDB, traceroute)
   - Add flows directly to HopGraph for visualization

10. **Production-Grade Architecture**
    - Dual ingestion: Live streaming (webhooks, Pub/Sub, Event Hubs) + Manual upload (CSV/JSON/PCAP)
    - 3-level enrichment strategy (minimal/standard/full) for cost control
    - Modular detector pipeline (easy to add new network protocols)
    - Scalable cloud-native deployment (Kubernetes, Terraform)

---

### Weaknesses

1. **Complex Implementation Scope**
   - Network infrastructure monitoring requires deep protocol expertise (BGP, OSPF, IPsec, VXLAN)
   - Integration with multiple cloud providers (AWS, Azure, GCP, Oracle, VMware, OpenStack) is engineering-intensive
   - CCIE-level tools require extensive network engineering domain knowledge

2. **Data Source Dependencies**
   - Relies on customers exporting VPC Flow Logs, BGP logs, IPsec logs, VXLAN logs
   - Some customers may not have infrastructure logging enabled
   - Requires API access to cloud providers (AWS CloudWatch, Azure Monitor, GCP Cloud Logging)

3. **Niche Expertise Required**
   - Network infrastructure security is specialized domain (fewer buyers than general endpoint/SIEM)
   - Target buyers: Large enterprises, cloud service providers, ISPs, financial institutions
   - Smaller SMBs may not need BGP/OSPF/VXLAN monitoring

4. **LLM Cost Uncertainty**
   - Even with gates, Tier 1/Tier 2 LLM costs for high-volume networks (100K+ flows/day) could be significant
   - Need transparent cost calculator for customers
   - Risk of sticker shock if LLM costs exceed expected budget

5. **Limited Attack Surface vs. EDR**
   - Network infrastructure attacks are less frequent than endpoint malware
   - May be harder to demonstrate ROI vs. endpoint-focused solutions
   - Customers may deprioritize network security if no recent BGP/OSPF incidents

6. **Competitor Maturity in Adjacent Spaces**
   - Darktrace, Vectra (network behavior analysis - mature, well-funded)
   - Splunk, Rapid7 (SIEM - can ingest network logs, though not specialized)
   - Cloud-native tools (AWS GuardDuty, Azure Sentinel - tight cloud integration)

---

### Opportunities

1. **$100M+ Market Gap**
   - **No competitor** correlates network infrastructure + endpoint + cloud in single platform
   - Darktrace/Vectra focus on network behavior, not infrastructure protocols
   - CrowdStrike/SentinelOne focus on endpoint, not network routing/VPN
   - JanuSec uniquely positioned to fill this gap

2. **Cloud Migration Tailwind**
   - Enterprises moving to multi-cloud (AWS + Azure + GCP) need unified network security
   - Hybrid cloud (on-prem + cloud) creates complex network attack surface
   - JanuSec's cloud-agnostic approach solves multi-cloud visibility problem

3. **Regulatory Compliance Drivers**
   - PCI-DSS 4.0: Requires network segmentation monitoring (VXLAN use case)
   - NIST Cybersecurity Framework: Network infrastructure resilience
   - FedRAMP: IPsec/VPN security auditing for government clouds
   - GDPR: Cross-border data flow monitoring (Geo enrichment use case)

4. **High-Profile BGP Incidents**
   - Recent BGP hijacks (Cloudflare 2020, Amazon Route 53 2018) raise awareness
   - ISPs and cloud providers increasingly worried about route security
   - RPKI adoption growing (JanuSec's RPKI validation feature is timely)

5. **Network as Attack Vector Trend**
   - Attackers increasingly targeting network infrastructure (BGP hijacks for crypto theft, route leaks for espionage)
   - Supply chain attacks via compromised network devices (SolarWinds, Juniper backdoor)
   - JanuSec's network forensics capabilities address emerging threat landscape

6. **Managed Security Service Providers (MSSPs)**
   - MSSPs need multi-tenant, multi-cloud platform
   - JanuSec's tenant isolation + cloud-agnostic design ideal for MSSP use case
   - Large MSSP customer could scale to 100s of end customers

7. **Integration Partnerships**
   - Partner with Zeek, Suricata (open-source network monitoring)
   - Partner with Cisco, Juniper (network device vendors - OEM opportunity)
   - Partner with cloud providers (AWS Marketplace, Azure Marketplace, GCP Marketplace)

8. **Threat Hunting Services**
   - Offer "Network Threat Hunting as a Service" using pre-built hunt queries
   - Target large enterprises without in-house network security expertise
   - Recurring revenue model (monthly hunt retainer)

---

### Threats

1. **Competitor Response**
   - Darktrace/Vectra could add network infrastructure protocol support
   - CrowdStrike/SentinelOne could acquire network security startup
   - Splunk/Rapid7 could enhance SIEM with network-specific detections

2. **Cloud Provider Native Tools**
   - AWS GuardDuty, Azure Sentinel, GCP Security Command Center improving
   - Customers may prefer "all-in-one" cloud provider security over third-party
   - JanuSec needs strong differentiation (cross-cloud correlation, HopGraph)

3. **Open-Source Alternatives**
   - Zeek, Suricata (free network monitoring)
   - ELK Stack (free log aggregation + SIEM)
   - Customers may try to build DIY solution using open-source tools

4. **Budget Constraints**
   - Network security may be deprioritized vs. endpoint/SIEM in tight budgets
   - CISOs may view BGP/OSPF monitoring as "nice to have" not "must have"
   - Need to demonstrate clear ROI (prevented BGP hijack = $X million saved)

5. **Complexity Barrier**
   - Customers may find network infrastructure security too complex to deploy
   - Requires expertise in BGP, OSPF, IPsec, VXLAN (not all security teams have this)
   - Need excellent onboarding, documentation, training, support

6. **LLM Cost Volatility**
   - OpenAI/Anthropic pricing changes could impact economics
   - Need to support multiple LLM providers (OpenAI, Anthropic, Ollama local) for cost flexibility
   - LLM cost increases could erode margins or force price hikes

7. **Regulatory Changes**
   - New privacy laws could restrict cross-border network log collection
   - Export controls on security tools (ITAR, EAR) could limit international sales
   - Need legal compliance for global sales

---

### Strategic Recommendations

1. **Target High-Value Customers First**
   - Focus on large enterprises, ISPs, cloud service providers, financial institutions
   - These buyers have network infrastructure and budget for specialized tools
   - Land-and-expand: Start with network module, upsell endpoint/cloud later

2. **Demonstrate ROI with Case Studies**
   - Document real-world BGP hijack prevented, route leak detected
   - Calculate cost of prevented incident ($1M data breach avoided = easy ROI justification)
   - Create reference architecture for multi-cloud deployments

3. **Invest in Partnerships**
   - Partner with Cisco, Juniper for OEM/reseller channel
   - Partner with AWS, Azure, GCP for marketplace listings
   - Partner with MSSPs for multi-tenant deployment

4. **Build Comprehensive Documentation**
   - CCIE-level network engineer guides
   - SOC analyst playbooks
   - Cloud deployment runbooks (Terraform, CloudFormation, ARM templates)
   - Video tutorials for complex features

5. **Offer Managed Service Tier**
   - "Network Threat Hunting as a Service" for customers without in-house expertise
   - Monthly retainer for threat hunting reports
   - Incident response retainer for BGP hijack / route leak emergencies

6. **Transparent Cost Calculator**
   - Interactive pricing calculator showing LLM costs based on flow volume
   - Show cost comparison: JanuSec vs. hiring dedicated network security engineer ($150K/year)
   - Demonstrate cost gates reducing LLM spend by 70-80%

7. **Open-Source Community Engagement**
   - Contribute to Zeek, Suricata projects
   - Publish open-source HopGraph library
   - Build community around network security best practices

---

## Summary

### What Was Added to `NETWORK_INFRASTRUCTURE_SECURITY.md`:

**Section 14: Forensic Analysis Tools**
- Network packet capture analysis (PCAP parsing for BGP/IPsec/VXLAN)
- Flow timeline reconstruction (correlate multi-source logs)
- Chain of custody management (evidence integrity, court admissibility)

**Section 15: CCIE-Level Network Analysis**
- BGP policy analyzer (route-map audits, AS-PATH validation, security scoring)
- OSPF adjacency debugger (MTU, area, auth, timer mismatch diagnosis)
- IPsec Phase 1/2 diagnostic tool (crypto mismatch, NAT-T, PFS debugging)
- VXLAN troubleshooter (VTEP reachability, MAC learning, MTU overhead)
- Network latency/jitter analyzer (per-hop latency, quality scoring)

**Section 16: CSV UI Enhancements**
- `csv_deep_analyze.html`: Risk-based row highlighting, inline network enrichments (ASN, Geo, RPKI, threat intel, port risk), one-click investigation tools (WHOIS, BGPmon, PeeringDB, ASN lookup), playbook execution buttons, add-to-HopGraph functionality
- `csv_analyze.html`: Network summary panel (total flows, unique IPs, data transferred), anomaly counters (BGP hijacks, route leaks, IPsec downgrades, VXLAN issues, port scans), geographic distribution map, top ASNs list

**Section 17: Playbook Integration**
- BGP Hijack Response Playbook (RPKI validation, BGPmon query, WHOIS lookup, ROA check, abuse notification, incident report)
- Route Leak Containment Playbook (scope analysis, BGP filter generation, upstream provider notification, BGP table monitoring)
- IPsec Hardening Playbook (config audit, crypto upgrade recommendations, hardened config generation, lab testing instructions)

**Section 18: SWOT Analysis**
- **Strengths**: Unique market position (only platform correlating network + endpoint + cloud), cloud-agnostic multi-cloud support, cost-optimized AI triage, CCIE-level tools, network forensics, pre-built hunt queries, playbook automation, persona-based reporting, comprehensive CSV UI, production-grade architecture
- **Weaknesses**: Complex implementation scope, data source dependencies, niche expertise required, LLM cost uncertainty, limited attack surface vs. EDR, competitor maturity
- **Opportunities**: $100M+ market gap, cloud migration tailwind, regulatory compliance drivers, high-profile BGP incidents, network as attack vector trend, MSSP market, integration partnerships, threat hunting services
- **Threats**: Competitor response, cloud provider native tools, open-source alternatives, budget constraints, complexity barrier, LLM cost volatility, regulatory changes
- **Strategic Recommendations**: Target high-value customers, demonstrate ROI with case studies, invest in partnerships, build comprehensive documentation, offer managed service tier, transparent cost calculator, open-source community engagement

---

### 1.1 Threats

| Threat | Description | Impact | Detection Difficulty |
|--------|-------------|--------|---------------------|
| **Route Hijacking** | Attacker announces more-specific prefix, traffic diverted | Data theft, MITM | Hard (looks legitimate) |
| **Route Leak** | Misconfiguration causes internal routes to leak externally | Information disclosure | Medium |
| **AS Path Manipulation** | Attacker prepends fake AS numbers to influence routing | Traffic engineering abuse | Medium |
| **Neighbor Session Hijacking** | TCP session hijacking to inject false routes | Full routing table control | Hard |
| **Max-Prefix DoS** | Flood peer with routes until max-prefix limit triggers | Service disruption | Easy |
| **Community Attribute Abuse** | Manipulate BGP communities to bypass policies | Policy evasion | Hard |

### 1.2 Detection Mechanisms

```python
"""
ibgp_security.py - iBGP threat detection
"""
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
import ipaddress


@dataclass
class BGPUpdate:
    """BGP UPDATE message"""
    timestamp: datetime
    peer_ip: str
    peer_asn: int
    nlri: List[str]  # Network Layer Reachability Information (prefixes)
    withdrawn: List[str]
    as_path: List[int]
    next_hop: str
    communities: List[str]
    origin: str  # IGP, EGP, INCOMPLETE


@dataclass
class BGPAnomaly:
    """Detected BGP anomaly"""
    anomaly_type: str
    severity: str  # critical, high, medium, low
    confidence: float
    description: str
    affected_prefixes: List[str]
    evidence: Dict
    mitre_techniques: List[str]
    recommended_action: str


class IBGPSecurityMonitor:
    """
    iBGP security monitoring with threat detection
    """

    def __init__(self):
        # Baseline data
        self.known_prefixes: Dict[str, Set[int]] = {}  # prefix -> set of ASNs that announce it
        self.known_as_paths: Dict[str, List[List[int]]] = {}  # prefix -> historical AS paths
        self.peer_uptime: Dict[str, datetime] = {}
        self.prefix_stability: Dict[str, int] = {}  # Number of updates in last hour

        # Threat intel feeds
        self.hijacked_prefixes: Set[str] = set()  # From threat intel
        self.suspicious_asns: Set[int] = set()

    # ====================================================================
    # DETECTION: PREFIX HIJACKING
    # ====================================================================

    def detect_prefix_hijacking(self, update: BGPUpdate) -> List[BGPAnomaly]:
        """
        Detect BGP prefix hijacking.

        Indicators:
        - More-specific prefix announced than known aggregate
        - Prefix announced by new ASN without AS_PATH from origin
        - Sudden change in origin ASN
        - Prefix matches threat intel feed
        """
        anomalies = []

        for prefix in update.nlri:
            # Check 1: Known prefix announced by new AS
            if prefix in self.known_prefixes:
                historical_asns = self.known_prefixes[prefix]
                current_origin_asn = update.as_path[-1] if update.as_path else update.peer_asn

                if current_origin_asn not in historical_asns:
                    # New origin ASN - possible hijack
                    anomalies.append(BGPAnomaly(
                        anomaly_type='prefix_hijack_new_origin',
                        severity='critical',
                        confidence=0.85,
                        description=f'Prefix {prefix} announced by new origin AS{current_origin_asn}, historically seen from {historical_asns}',
                        affected_prefixes=[prefix],
                        evidence={
                            'historical_asns': list(historical_asns),
                            'current_asn': current_origin_asn,
                            'as_path': update.as_path,
                            'peer': update.peer_ip
                        },
                        mitre_techniques=['T1498.001'],  # Network DoS
                        recommended_action='Verify prefix ownership with RPKI or contact peer AS network team'
                    ))

            # Check 2: More-specific prefix (sub-prefix attack)
            for known_prefix in self.known_prefixes.keys():
                try:
                    known_net = ipaddress.ip_network(known_prefix)
                    announced_net = ipaddress.ip_network(prefix)

                    # If announced prefix is more specific (subnet of known)
                    if announced_net.subnet_of(known_net) and prefix != known_prefix:
                        anomalies.append(BGPAnomaly(
                            anomaly_type='prefix_hijack_more_specific',
                            severity='critical',
                            confidence=0.90,
                            description=f'More-specific prefix {prefix} announced, subset of {known_prefix}',
                            affected_prefixes=[prefix, known_prefix],
                            evidence={
                                'parent_prefix': known_prefix,
                                'hijack_prefix': prefix,
                                'announcing_asn': update.as_path[-1] if update.as_path else update.peer_asn
                            },
                            mitre_techniques=['T1498.001', 'T1557.002'],  # MITM
                            recommended_action='URGENT: Validate prefix ownership. More-specific hijacks are common attack vector.'
                        ))
                except ValueError:
                    pass  # Invalid prefix format

            # Check 3: Threat intel match
            if prefix in self.hijacked_prefixes:
                anomalies.append(BGPAnomaly(
                    anomaly_type='prefix_hijack_threat_intel',
                    severity='critical',
                    confidence=0.95,
                    description=f'Prefix {prefix} matches known hijacked prefix from threat intel',
                    affected_prefixes=[prefix],
                    evidence={
                        'threat_intel_source': 'BGPmon/RIPE',
                        'as_path': update.as_path
                    },
                    mitre_techniques=['T1498.001'],
                    recommended_action='BLOCK: Known hijacked prefix. Filter immediately.'
                ))

        return anomalies

    # ====================================================================
    # DETECTION: ROUTE LEAK
    # ====================================================================

    def detect_route_leak(self, update: BGPUpdate, internal_asns: Set[int]) -> List[BGPAnomaly]:
        """
        Detect route leaks (internal routes announced externally).

        Indicators:
        - Internal ASN appears in AS_PATH to external peer
        - RFC1918 prefixes announced to external peer
        - Routes with NO_EXPORT community leaked
        """
        anomalies = []

        # Check 1: Internal ASN in path to external peer
        if update.peer_asn not in internal_asns:
            # This is an external peer
            leaked_asns = [asn for asn in update.as_path if asn in internal_asns]
            if leaked_asns:
                anomalies.append(BGPAnomaly(
                    anomaly_type='route_leak_internal_as',
                    severity='high',
                    confidence=0.80,
                    description=f'Internal AS numbers {leaked_asns} leaked to external peer AS{update.peer_asn}',
                    affected_prefixes=update.nlri,
                    evidence={
                        'leaked_asns': leaked_asns,
                        'external_peer': update.peer_asn,
                        'full_as_path': update.as_path
                    },
                    mitre_techniques=['T1498.001', 'T1590.002'],  # Network topology discovery
                    recommended_action='Review BGP filters. Internal routes should not be announced externally.'
                ))

        # Check 2: RFC1918 prefixes to external peer
        RFC1918_PREFIXES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        if update.peer_asn not in internal_asns:
            for prefix in update.nlri:
                try:
                    announced_net = ipaddress.ip_network(prefix)
                    for rfc1918 in RFC1918_PREFIXES:
                        rfc1918_net = ipaddress.ip_network(rfc1918)
                        if announced_net.subnet_of(rfc1918_net):
                            anomalies.append(BGPAnomaly(
                                anomaly_type='route_leak_rfc1918',
                                severity='critical',
                                confidence=0.95,
                                description=f'RFC1918 prefix {prefix} leaked to external peer',
                                affected_prefixes=[prefix],
                                evidence={
                                    'rfc1918_parent': rfc1918,
                                    'external_peer': update.peer_asn
                                },
                                mitre_techniques=['T1590.005'],  # Network mapping
                                recommended_action='URGENT: Filter RFC1918 prefixes from external announcements'
                            ))
                except ValueError:
                    pass

        # Check 3: NO_EXPORT community leaked
        if 'NO_EXPORT' in update.communities or '65535:65281' in update.communities:
            if update.peer_asn not in internal_asns:
                anomalies.append(BGPAnomaly(
                    anomaly_type='route_leak_no_export',
                    severity='high',
                    confidence=0.90,
                    description='Route with NO_EXPORT community leaked to external peer',
                    affected_prefixes=update.nlri,
                    evidence={
                        'communities': update.communities,
                        'external_peer': update.peer_asn
                    },
                    mitre_techniques=['T1498.001'],
                    recommended_action='Check BGP policy. NO_EXPORT routes should stay within AS.'
                ))

        return anomalies

    # ====================================================================
    # DETECTION: AS PATH MANIPULATION
    # ====================================================================

    def detect_as_path_manipulation(self, update: BGPUpdate) -> List[BGPAnomaly]:
        """
        Detect AS_PATH manipulation.

        Indicators:
        - AS_PATH contains private ASNs (64512-65534)
        - AS_PATH has unusual length (>10 hops)
        - AS_PATH has loops
        - AS_PATH differs significantly from historical paths
        """
        anomalies = []

        # Check 1: Private ASN in path
        PRIVATE_ASN_START = 64512
        PRIVATE_ASN_END = 65534

        private_asns = [asn for asn in update.as_path
                       if PRIVATE_ASN_START <= asn <= PRIVATE_ASN_END]
        if private_asns:
            anomalies.append(BGPAnomaly(
                anomaly_type='as_path_private_asn',
                severity='medium',
                confidence=0.70,
                description=f'AS_PATH contains private ASNs: {private_asns}',
                affected_prefixes=update.nlri,
                evidence={
                    'private_asns': private_asns,
                    'full_path': update.as_path
                },
                mitre_techniques=['T1590.002'],
                recommended_action='Investigate peer configuration. Private ASNs should be filtered.'
            ))

        # Check 2: AS_PATH too long
        if len(update.as_path) > 10:
            anomalies.append(BGPAnomaly(
                anomaly_type='as_path_too_long',
                severity='medium',
                confidence=0.60,
                description=f'AS_PATH length {len(update.as_path)} exceeds normal (>10 hops)',
                affected_prefixes=update.nlri,
                evidence={
                    'path_length': len(update.as_path),
                    'full_path': update.as_path
                },
                mitre_techniques=['T1498.001'],
                recommended_action='Possible AS_PATH prepending abuse or routing loop'
            ))

        # Check 3: AS_PATH loop detection
        if len(update.as_path) != len(set(update.as_path)):
            # Duplicates exist - loop detected
            from collections import Counter
            asn_counts = Counter(update.as_path)
            looped_asns = [asn for asn, count in asn_counts.items() if count > 1]

            anomalies.append(BGPAnomaly(
                anomaly_type='as_path_loop',
                severity='high',
                confidence=0.85,
                description=f'AS_PATH loop detected: {looped_asns} appear multiple times',
                affected_prefixes=update.nlri,
                evidence={
                    'looped_asns': looped_asns,
                    'full_path': update.as_path
                },
                mitre_techniques=['T1498.001'],
                recommended_action='Routing loop detected. Check for misconfiguration or attack.'
            ))

        # Check 4: Historical path deviation
        for prefix in update.nlri:
            if prefix in self.known_as_paths:
                historical_paths = self.known_as_paths[prefix]
                current_path = update.as_path

                # Simple similarity: Check if current path shares ASNs with historical
                path_similarity = len(set(current_path) & set(sum(historical_paths, []))) / len(set(current_path))

                if path_similarity < 0.3:  # Less than 30% overlap
                    anomalies.append(BGPAnomaly(
                        anomaly_type='as_path_deviation',
                        severity='medium',
                        confidence=0.65,
                        description=f'AS_PATH for {prefix} deviates significantly from historical',
                        affected_prefixes=[prefix],
                        evidence={
                            'current_path': current_path,
                            'historical_paths': historical_paths[:3],  # Show 3 examples
                            'similarity': path_similarity
                        },
                        mitre_techniques=['T1590.002'],
                        recommended_action='Investigate path change. Could be legitimate route optimization or attack.'
                    ))

        return anomalies

    # ====================================================================
    # DETECTION: BGP SESSION HIJACKING
    # ====================================================================

    def detect_session_anomalies(self, session_event: Dict) -> List[BGPAnomaly]:
        """
        Detect BGP session hijacking or DoS.

        Indicators:
        - Peer flapping (rapid up/down)
        - New peer from unexpected IP
        - Session from IP not in peer configuration
        - Max-prefix threshold reached
        """
        anomalies = []

        peer_ip = session_event.get('peer_ip')
        event_type = session_event.get('type')  # 'established', 'down', 'max_prefix'

        # Check 1: Peer flapping
        if event_type == 'down':
            if peer_ip in self.peer_uptime:
                uptime = datetime.utcnow() - self.peer_uptime[peer_ip]
                if uptime < timedelta(minutes=5):
                    anomalies.append(BGPAnomaly(
                        anomaly_type='bgp_peer_flapping',
                        severity='high',
                        confidence=0.80,
                        description=f'BGP peer {peer_ip} flapping (uptime < 5 min)',
                        affected_prefixes=[],
                        evidence={
                            'peer': peer_ip,
                            'uptime_seconds': uptime.total_seconds()
                        },
                        mitre_techniques=['T1498'],  # DoS
                        recommended_action='Investigate peer connectivity. Could be DoS attack on BGP session.'
                    ))

        # Check 2: Max-prefix DoS
        if event_type == 'max_prefix':
            anomalies.append(BGPAnomaly(
                anomaly_type='bgp_max_prefix_dos',
                severity='critical',
                confidence=0.90,
                description=f'BGP peer {peer_ip} exceeded max-prefix limit',
                affected_prefixes=[],
                evidence={
                    'peer': peer_ip,
                    'max_prefix_limit': session_event.get('limit')
                },
                mitre_techniques=['T1498.001'],
                recommended_action='URGENT: Peer flooding routes. Likely DoS attack or misconfiguration.'
            ))

        return anomalies
```

### 1.3 RPKI Validation Integration

```python
def validate_rpki(prefix: str, origin_asn: int, rpki_validator_url: str = 'https://rpki-validator.ripe.net/api/v1/validity') -> Dict:
    """
    Validate BGP route against RPKI (Resource Public Key Infrastructure).

    Returns:
        {
            'state': 'valid' | 'invalid' | 'not_found',
            'roas': [...],  # Route Origin Authorizations
            'description': 'Human-readable status'
        }
    """
    import requests

    try:
        response = requests.get(
            rpki_validator_url,
            params={'prefix': prefix, 'asn': f'AS{origin_asn}'},
            timeout=5
        )

        data = response.json()

        if data['validated_route']['validity']['state'] == 'Valid':
            return {
                'state': 'valid',
                'description': f'Route {prefix} from AS{origin_asn} is RPKI valid'
            }
        elif data['validated_route']['validity']['state'] == 'Invalid':
            return {
                'state': 'invalid',
                'description': f'Route {prefix} from AS{origin_asn} is RPKI INVALID - possible hijack',
                'roas': data.get('roas', [])
            }
        else:
            return {
                'state': 'not_found',
                'description': 'No RPKI ROA found for this prefix'
            }
    except Exception as e:
        return {
            'state': 'error',
            'description': f'RPKI validation failed: {str(e)}'
        }
```

---

## OSPF Security

### 2.1 Threats

| Threat | Description | Impact | Detection Difficulty |
|--------|-------------|--------|---------------------|
| **LSA Flooding** | Flood network with fake LSAs (Link State Advertisements) | CPU exhaustion, routing instability | Medium |
| **Neighbor Spoofing** | Inject false OSPF hellos to form adjacencies | Routing table manipulation | Hard (requires auth bypass) |
| **Area Manipulation** | Advertise routes from wrong OSPF area | Suboptimal routing, loops | Medium |
| **Max-Age LSA DoS** | Send LSAs with max age to flush routes | Network outage | Easy |
| **Type-5 LSA Injection** | Inject external routes (Type-5 LSAs) | Blackhole traffic | Medium |
| **Router ID Spoofing** | Use same Router ID as legitimate router | Split-brain routing | Hard |

### 2.2 Detection Mechanisms

```python
"""
ospf_security.py - OSPF threat detection
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime
import ipaddress


@dataclass
class OSPFPacket:
    """OSPF packet (Hello, DBD, LSR, LSU, LSAck)"""
    timestamp: datetime
    packet_type: str  # hello, dbd, lsr, lsu, lsack
    router_id: str
    area_id: str
    source_ip: str
    auth_type: int  # 0=null, 1=simple, 2=md5
    neighbor_count: int = 0
    lsas: List[Dict] = None  # For LSU packets


@dataclass
class OSPFAnomaly:
    """Detected OSPF anomaly"""
    anomaly_type: str
    severity: str
    confidence: float
    description: str
    affected_routers: List[str]
    evidence: Dict
    mitre_techniques: List[str]
    recommended_action: str


class OSPFSecurityMonitor:
    """
    OSPF security monitoring with threat detection
    """

    def __init__(self):
        self.known_routers: Dict[str, Dict] = {}  # router_id -> metadata
        self.area_topology: Dict[str, Set[str]] = {}  # area_id -> set of router_ids
        self.lsa_database: Dict[str, Dict] = {}  # LSA key -> LSA data
        self.hello_intervals: Dict[str, List[datetime]] = {}

    # ====================================================================
    # DETECTION: LSA FLOODING
    # ====================================================================

    def detect_lsa_flooding(self, packet: OSPFPacket, window_seconds: int = 60) -> List[OSPFAnomaly]:
        """
        Detect LSA flooding attack.

        Indicators:
        - Excessive LSAs from single router (>100/min)
        - LSAs with seq numbers jumping (0x80000001 to 0x7fffffff)
        - Duplicate LSAs with minor changes
        """
        anomalies = []

        if packet.packet_type != 'lsu':  # Link State Update
            return anomalies

        router_id = packet.router_id

        # Count LSAs from this router in time window
        recent_lsas = [
            lsa for lsa in self.lsa_database.values()
            if lsa.get('advertising_router') == router_id
            and (datetime.utcnow() - lsa.get('timestamp', datetime.min)).total_seconds() < window_seconds
        ]

        if len(recent_lsas) > 100:
            anomalies.append(OSPFAnomaly(
                anomaly_type='ospf_lsa_flooding',
                severity='critical',
                confidence=0.90,
                description=f'Router {router_id} sent {len(recent_lsas)} LSAs in {window_seconds}s (threshold: 100)',
                affected_routers=[router_id],
                evidence={
                    'router_id': router_id,
                    'lsa_count': len(recent_lsas),
                    'time_window': window_seconds
                },
                mitre_techniques=['T1498'],  # DoS
                recommended_action='URGENT: LSA flood detected. Isolate router or enable LSA throttling.'
            ))

        # Check for sequence number manipulation
        if packet.lsas:
            for lsa in packet.lsas:
                seq_num = lsa.get('seq_number', 0)
                # Max seq is 0x7fffffff, if we see jump to near-max, suspicious
                if seq_num > 0x7fff0000:
                    anomalies.append(OSPFAnomaly(
                        anomaly_type='ospf_lsa_seq_manipulation',
                        severity='high',
                        confidence=0.75,
                        description=f'LSA with suspicious seq number 0x{seq_num:x} from {router_id}',
                        affected_routers=[router_id],
                        evidence={
                            'lsa_type': lsa.get('type'),
                            'seq_number': hex(seq_num),
                            'advertising_router': router_id
                        },
                        mitre_techniques=['T1498'],
                        recommended_action='Investigate LSA sequence. May indicate attempt to override legitimate LSAs.'
                    ))

        return anomalies

    # ====================================================================
    # DETECTION: NEIGHBOR SPOOFING
    # ====================================================================

    def detect_neighbor_spoofing(self, packet: OSPFPacket) -> List[OSPFAnomaly]:
        """
        Detect OSPF neighbor spoofing.

        Indicators:
        - New router ID from unexpected subnet
        - Same router ID from multiple IPs
        - Router with null authentication in MD5 area
        """
        anomalies = []

        if packet.packet_type != 'hello':
            return anomalies

        router_id = packet.router_id
        source_ip = packet.source_ip

        # Check 1: Same router ID from different IPs
        if router_id in self.known_routers:
            known_ip = self.known_routers[router_id].get('source_ip')
            if known_ip and known_ip != source_ip:
                anomalies.append(OSPFAnomaly(
                    anomaly_type='ospf_router_id_conflict',
                    severity='critical',
                    confidence=0.95,
                    description=f'Router ID {router_id} seen from multiple IPs: {known_ip}, {source_ip}',
                    affected_routers=[router_id],
                    evidence={
                        'router_id': router_id,
                        'known_ip': known_ip,
                        'current_ip': source_ip
                    },
                    mitre_techniques=['T1557'],  # MITM
                    recommended_action='URGENT: Router ID conflict. Possible spoofing attack.'
                ))

        # Check 2: Authentication mismatch
        area_id = packet.area_id
        if area_id in self.area_topology:
            # Check if other routers in this area use stronger auth
            area_routers = self.area_topology[area_id]
            area_auth_types = [
                self.known_routers.get(rid, {}).get('auth_type', 0)
                for rid in area_routers
            ]

            if area_auth_types and max(area_auth_types) > packet.auth_type:
                anomalies.append(OSPFAnomaly(
                    anomaly_type='ospf_auth_downgrade',
                    severity='high',
                    confidence=0.80,
                    description=f'Router {router_id} using weaker auth (type {packet.auth_type}) than area standard',
                    affected_routers=[router_id],
                    evidence={
                        'router_auth': packet.auth_type,
                        'area_auth_max': max(area_auth_types),
                        'area_id': area_id
                    },
                    mitre_techniques=['T1557'],
                    recommended_action='Enforce consistent authentication across OSPF area.'
                ))

        return anomalies

    # ====================================================================
    # DETECTION: TYPE-5 LSA INJECTION (EXTERNAL ROUTES)
    # ====================================================================

    def detect_malicious_external_routes(self, packet: OSPFPacket, trusted_asbrs: Set[str]) -> List[OSPFAnomaly]:
        """
        Detect malicious external route injection.

        Indicators:
        - Type-5 LSA from non-ASBR router
        - External route to RFC1918 space
        - External route to public infra (8.8.8.8, etc.)
        """
        anomalies = []

        if packet.packet_type != 'lsu' or not packet.lsas:
            return anomalies

        for lsa in packet.lsas:
            if lsa.get('type') != 5:  # Type-5 = AS-External-LSA
                continue

            advertising_router = lsa.get('advertising_router')
            network = lsa.get('network')

            # Check 1: Type-5 from non-ASBR
            if advertising_router not in trusted_asbrs:
                anomalies.append(OSPFAnomaly(
                    anomaly_type='ospf_unauthorized_asbr',
                    severity='critical',
                    confidence=0.85,
                    description=f'Type-5 LSA from unauthorized router {advertising_router}',
                    affected_routers=[advertising_router],
                    evidence={
                        'advertising_router': advertising_router,
                        'network': network,
                        'trusted_asbrs': list(trusted_asbrs)
                    },
                    mitre_techniques=['T1498.001', 'T1557'],
                    recommended_action='URGENT: Unauthorized ASBR. Filter Type-5 LSAs from this router.'
                ))

            # Check 2: External route to RFC1918
            RFC1918 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
            try:
                net = ipaddress.ip_network(network)
                for rfc in RFC1918:
                    if net.overlaps(ipaddress.ip_network(rfc)):
                        anomalies.append(OSPFAnomaly(
                            anomaly_type='ospf_rfc1918_external',
                            severity='high',
                            confidence=0.75,
                            description=f'Type-5 LSA advertising RFC1918 prefix {network}',
                            affected_routers=[advertising_router],
                            evidence={
                                'network': network,
                                'rfc1918_parent': rfc,
                                'advertising_router': advertising_router
                            },
                            mitre_techniques=['T1498.001'],
                            recommended_action='Investigate. RFC1918 should not be external routes.'
                        ))
            except ValueError:
                pass

            # Check 3: Critical infrastructure routes
            CRITICAL_PREFIXES = ['8.8.8.0/24', '1.1.1.0/24']  # Google DNS, Cloudflare
            try:
                net = ipaddress.ip_network(network)
                for crit in CRITICAL_PREFIXES:
                    if net.overlaps(ipaddress.ip_network(crit)):
                        anomalies.append(OSPFAnomaly(
                            anomaly_type='ospf_critical_prefix_hijack',
                            severity='critical',
                            confidence=0.90,
                            description=f'Type-5 LSA attempting to hijack critical prefix {network}',
                            affected_routers=[advertising_router],
                            evidence={
                                'network': network,
                                'critical_prefix': crit,
                                'advertising_router': advertising_router
                            },
                            mitre_techniques=['T1498.001', 'T1557.002'],
                            recommended_action='URGENT: Block immediately. Attempted hijack of critical infrastructure.'
                        ))
            except ValueError:
                pass

        return anomalies
```

---

## IPsec Security

### 3.1 Threats

| Threat | Description | Impact | Detection Difficulty |
|--------|-------------|--------|---------------------|
| **Tunnel Downgrade** | Force downgrade to weak crypto (DES, MD5) | Decryption of traffic | Hard |
| **IKE Exhaustion** | Flood with IKE handshakes to exhaust resources | DoS | Easy |
| **Replay Attack** | Replay captured ESP packets | Data injection | Medium (if anti-replay disabled) |
| **DPD Manipulation** | Manipulate Dead Peer Detection to tear down tunnels | Service disruption | Medium |
| **Certificate Validation Bypass** | Accept expired/revoked certificates | MITM | Hard |
| **NAT-T Abuse** | Manipulate NAT traversal to bypass firewall | Firewall bypass | Medium |

### 3.2 Detection Mechanisms

```python
"""
ipsec_security.py - IPsec tunnel monitoring and threat detection
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime, timedelta


@dataclass
class IPsecTunnel:
    """IPsec tunnel metadata"""
    tunnel_id: str
    local_ip: str
    remote_ip: str
    ike_version: int  # 1 or 2
    encryption: str  # AES-256-GCM, AES-128-CBC, 3DES, DES
    integrity: str  # SHA256, SHA1, MD5
    dh_group: int  # 14, 5, 2, 1
    pfs: bool  # Perfect Forward Secrecy enabled
    established_at: datetime
    last_rekey: Optional[datetime]
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int


@dataclass
class IPsecAnomaly:
    """IPsec security anomaly"""
    anomaly_type: str
    severity: str
    confidence: float
    description: str
    affected_tunnels: List[str]
    evidence: Dict
    mitre_techniques: List[str]
    recommended_action: str


class IPsecSecurityMonitor:
    """
    IPsec tunnel security monitoring
    """

    def __init__(self):
        self.tunnels: Dict[str, IPsecTunnel] = {}
        self.baseline_crypto: Dict[str, str] = {}  # tunnel_id -> expected crypto
        self.tunnel_flap_count: Dict[str, int] = {}

    # ====================================================================
    # DETECTION: WEAK CRYPTOGRAPHY / DOWNGRADE ATTACKS
    # ====================================================================

    def detect_weak_crypto(self, tunnel: IPsecTunnel) -> List[IPsecAnomaly]:
        """
        Detect weak cryptographic parameters.

        Red flags:
        - DES, 3DES encryption
        - MD5 integrity
        - DH group 1, 2, 5 (weak)
        - No PFS
        """
        anomalies = []

        # Check encryption strength
        WEAK_ENCRYPTION = ['DES', '3DES', 'NULL']
        if any(weak in tunnel.encryption.upper() for weak in WEAK_ENCRYPTION):
            anomalies.append(IPsecAnomaly(
                anomaly_type='ipsec_weak_encryption',
                severity='critical',
                confidence=0.95,
                description=f'Tunnel {tunnel.tunnel_id} using weak encryption: {tunnel.encryption}',
                affected_tunnels=[tunnel.tunnel_id],
                evidence={
                    'encryption': tunnel.encryption,
                    'remote_ip': tunnel.remote_ip,
                    'ike_version': tunnel.ike_version
                },
                mitre_techniques=['T1557', 'T1600.001'],  # Crypto downgrade
                recommended_action='URGENT: Upgrade to AES-256-GCM. DES/3DES are broken.'
            ))

        # Check integrity algorithm
        WEAK_INTEGRITY = ['MD5', 'NULL']
        if any(weak in tunnel.integrity.upper() for weak in WEAK_INTEGRITY):
            anomalies.append(IPsecAnomaly(
                anomaly_type='ipsec_weak_integrity',
                severity='high',
                confidence=0.90,
                description=f'Tunnel {tunnel.tunnel_id} using weak integrity: {tunnel.integrity}',
                affected_tunnels=[tunnel.tunnel_id],
                evidence={
                    'integrity': tunnel.integrity,
                    'remote_ip': tunnel.remote_ip
                },
                mitre_techniques=['T1557', 'T1600.001'],
                recommended_action='Upgrade to SHA256 or SHA384. MD5 is cryptographically broken.'
            ))

        # Check DH group
        WEAK_DH_GROUPS = [1, 2, 5]  # Group 14+ recommended
        if tunnel.dh_group in WEAK_DH_GROUPS:
            anomalies.append(IPsecAnomaly(
                anomaly_type='ipsec_weak_dh_group',
                severity='high',
                confidence=0.85,
                description=f'Tunnel {tunnel.tunnel_id} using weak DH group {tunnel.dh_group}',
                affected_tunnels=[tunnel.tunnel_id],
                evidence={
                    'dh_group': tunnel.dh_group,
                    'remote_ip': tunnel.remote_ip
                },
                mitre_techniques=['T1600.001'],
                recommended_action='Use DH group 14+ (2048-bit) or group 19+ (ECC).'
            ))

        # Check PFS
        if not tunnel.pfs:
            anomalies.append(IPsecAnomaly(
                anomaly_type='ipsec_no_pfs',
                severity='medium',
                confidence=0.75,
                description=f'Tunnel {tunnel.tunnel_id} does not use Perfect Forward Secrecy',
                affected_tunnels=[tunnel.tunnel_id],
                evidence={
                    'pfs': tunnel.pfs,
                    'remote_ip': tunnel.remote_ip
                },
                mitre_techniques=['T1600.001'],
                recommended_action='Enable PFS to protect past sessions if keys are compromised.'
            ))

        return anomalies

    # ====================================================================
    # DETECTION: TUNNEL DOWNGRADE ATTACK
    # ====================================================================

    def detect_tunnel_downgrade(self, tunnel: IPsecTunnel) -> List[IPsecAnomaly]:
        """
        Detect downgrade from strong to weak crypto.

        Indicator: Tunnel previously used AES-256, now using 3DES
        """
        anomalies = []

        tunnel_id = tunnel.tunnel_id

        if tunnel_id in self.baseline_crypto:
            baseline = self.baseline_crypto[tunnel_id]
            current = f"{tunnel.encryption}/{tunnel.integrity}/DH{tunnel.dh_group}"

            # Simple strength scoring
            def crypto_strength(crypto_str):
                score = 0
                if 'AES-256' in crypto_str: score += 3
                elif 'AES-128' in crypto_str: score += 2
                elif '3DES' in crypto_str: score += 1

                if 'SHA256' in crypto_str or 'SHA384' in crypto_str: score += 2
                elif 'SHA1' in crypto_str: score += 1

                if 'DH14' in crypto_str or 'DH19' in crypto_str: score += 2
                elif 'DH5' in crypto_str: score += 1

                return score

            baseline_strength = crypto_strength(baseline)
            current_strength = crypto_strength(current)

            if current_strength < baseline_strength:
                anomalies.append(IPsecAnomaly(
                    anomaly_type='ipsec_crypto_downgrade',
                    severity='critical',
                    confidence=0.90,
                    description=f'Tunnel {tunnel_id} downgraded from {baseline} to {current}',
                    affected_tunnels=[tunnel_id],
                    evidence={
                        'baseline_crypto': baseline,
                        'current_crypto': current,
                        'baseline_strength': baseline_strength,
                        'current_strength': current_strength,
                        'remote_ip': tunnel.remote_ip
                    },
                    mitre_techniques=['T1557', 'T1600.001'],
                    recommended_action='URGENT: Crypto downgrade detected. Possible MITM attack. Verify peer authenticity.'
                ))
        else:
            # First time seeing tunnel, establish baseline
            self.baseline_crypto[tunnel_id] = f"{tunnel.encryption}/{tunnel.integrity}/DH{tunnel.dh_group}"

        return anomalies

    # ====================================================================
    # DETECTION: IKE EXHAUSTION / DoS
    # ====================================================================

    def detect_ike_exhaustion(self, ike_events: List[Dict], window_seconds: int = 60) -> List[IPsecAnomaly]:
        """
        Detect IKE handshake flooding.

        Indicators:
        - Excessive IKE_SA_INIT requests (>50/min from single IP)
        - Many failed authentications
        - Short-lived tunnels (est + tear down within seconds)
        """
        anomalies = []

        # Count IKE_SA_INIT by source IP
        init_counts: Dict[str, int] = {}
        failed_auth_counts: Dict[str, int] = {}

        cutoff_time = datetime.utcnow() - timedelta(seconds=window_seconds)

        for event in ike_events:
            if event.get('timestamp', datetime.min) < cutoff_time:
                continue

            source_ip = event.get('source_ip')
            event_type = event.get('type')

            if event_type == 'IKE_SA_INIT':
                init_counts[source_ip] = init_counts.get(source_ip, 0) + 1
            elif event_type == 'AUTH_FAILED':
                failed_auth_counts[source_ip] = failed_auth_counts.get(source_ip, 0) + 1

        # Check for flooding
        for source_ip, count in init_counts.items():
            if count > 50:
                anomalies.append(IPsecAnomaly(
                    anomaly_type='ipsec_ike_flooding',
                    severity='critical',
                    confidence=0.95,
                    description=f'IKE flooding from {source_ip}: {count} IKE_SA_INIT in {window_seconds}s',
                    affected_tunnels=[],
                    evidence={
                        'source_ip': source_ip,
                        'ike_init_count': count,
                        'time_window': window_seconds
                    },
                    mitre_techniques=['T1498'],  # DoS
                    recommended_action='URGENT: Block source IP. IKE DoS attack detected.'
                ))

        # Check for authentication bruteforce
        for source_ip, count in failed_auth_counts.items():
            if count > 10:
                anomalies.append(IPsecAnomaly(
                    anomaly_type='ipsec_auth_bruteforce',
                    severity='high',
                    confidence=0.85,
                    description=f'Failed auth bruteforce from {source_ip}: {count} failures in {window_seconds}s',
                    affected_tunnels=[],
                    evidence={
                        'source_ip': source_ip,
                        'failed_auth_count': count
                    },
                    mitre_techniques=['T1110'],  # Brute force
                    recommended_action='Block source IP. Possible PSK/certificate bruteforce.'
                ))

        return anomalies

    # ====================================================================
    # DETECTION: TUNNEL FLAPPING
    # ====================================================================

    def detect_tunnel_flapping(self, tunnel_id: str, event_type: str) -> List[IPsecAnomaly]:
        """
        Detect rapid tunnel up/down cycles.

        Indicators:
        - Tunnel down within 5 minutes of establishment
        - >3 flaps in 10 minutes
        """
        anomalies = []

        if event_type == 'down':
            self.tunnel_flap_count[tunnel_id] = self.tunnel_flap_count.get(tunnel_id, 0) + 1

            if self.tunnel_flap_count[tunnel_id] > 3:
                if tunnel_id in self.tunnels:
                    tunnel = self.tunnels[tunnel_id]
                    anomalies.append(IPsecAnomaly(
                        anomaly_type='ipsec_tunnel_flapping',
                        severity='high',
                        confidence=0.80,
                        description=f'Tunnel {tunnel_id} flapping: {self.tunnel_flap_count[tunnel_id]} downs recently',
                        affected_tunnels=[tunnel_id],
                        evidence={
                            'flap_count': self.tunnel_flap_count[tunnel_id],
                            'remote_ip': tunnel.remote_ip
                        },
                        mitre_techniques=['T1498', 'T1557'],
                        recommended_action='Investigate tunnel stability. Could be DPD manipulation or DoS.'
                    ))

        return anomalies
```

---

## VXLAN Security

### 4.1 Threats

| Threat | Description | Impact | Detection Difficulty |
|--------|-------------|--------|---------------------|
| **VTEP Spoofing** | Fake VXLAN Tunnel Endpoint joins overlay | VLAN hopping, eavesdropping | Hard |
| **VNI Injection** | Send packets with wrong VNI (Virtual Network Identifier) | Segment isolation bypass | Medium |
| **VXLAN Flood** | Flood overlay with broadcast traffic | DoS, performance degradation | Easy |
| **Malicious VTEP Registration** | Rogue VTEP joins multicast group | MITM on overlay traffic | Hard |
| **MAC Flooding** | Exhaust MAC learning table on VTEPs | Traffic flooding | Medium |
| **Underlay Attack** | Attack underlying IP network to disrupt overlay | Overlay outage | Medium |

### 4.2 Detection Mechanisms

```python
"""
vxlan_security.py - VXLAN overlay security monitoring
"""
from dataclasses import dataclass
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta


@dataclass
class VXLANPacket:
    """VXLAN encapsulated packet"""
    timestamp: datetime
    outer_src_ip: str  # VTEP source
    outer_dst_ip: str  # VTEP destination
    vni: int  # Virtual Network Identifier
    inner_src_mac: str
    inner_dst_mac: str
    inner_src_ip: Optional[str]
    inner_dst_ip: Optional[str]


@dataclass
class VXLANAnomaly:
    """VXLAN security anomaly"""
    anomaly_type: str
    severity: str
    confidence: float
    description: str
    affected_vnis: List[int]
    affected_vteps: List[str]
    evidence: Dict
    mitre_techniques: List[str]
    recommended_action: str


class VXLANSecurityMonitor:
    """
    VXLAN overlay network security monitoring
    """

    def __init__(self):
        self.known_vteps: Dict[int, Set[str]] = {}  # vni -> set of VTEP IPs
        self.vni_mac_table: Dict[int, Set[str]] = {}  # vni -> set of MACs
        self.vtep_registration_time: Dict[str, datetime] = {}
        self.vni_assignments: Dict[int, str] = {}  # vni -> tenant/segment name

    # ====================================================================
    # DETECTION: VTEP SPOOFING / ROGUE VTEP
    # ====================================================================

    def detect_rogue_vtep(self, packet: VXLANPacket, authorized_vteps: Dict[int, Set[str]]) -> List[VXLANAnomaly]:
        """
        Detect rogue VXLAN Tunnel Endpoints.

        Indicators:
        - VTEP not in authorized list for VNI
        - New VTEP appeared suddenly
        - VTEP sending packets for multiple VNIs (unusual)
        """
        anomalies = []

        vni = packet.vni
        vtep_ip = packet.outer_src_ip

        # Check 1: VTEP not authorized for this VNI
        if vni in authorized_vteps:
            if vtep_ip not in authorized_vteps[vni]:
                anomalies.append(VXLANAnomaly(
                    anomaly_type='vxlan_rogue_vtep',
                    severity='critical',
                    confidence=0.90,
                    description=f'Unauthorized VTEP {vtep_ip} sending traffic on VNI {vni}',
                    affected_vnis=[vni],
                    affected_vteps=[vtep_ip],
                    evidence={
                        'vtep_ip': vtep_ip,
                        'vni': vni,
                        'authorized_vteps': list(authorized_vteps[vni])
                    },
                    mitre_techniques=['T1557.002', 'T1599.001'],  # MITM, VLAN hopping
                    recommended_action='URGENT: Block VTEP immediately. Rogue endpoint detected.'
                ))

        # Check 2: New VTEP that wasn't bootstrapped
        if vtep_ip not in self.vtep_registration_time:
            # New VTEP - should have been registered via control plane
            anomalies.append(VXLANAnomaly(
                anomaly_type='vxlan_unregistered_vtep',
                severity='high',
                confidence=0.75,
                description=f'VTEP {vtep_ip} sending traffic but not in registry',
                affected_vnis=[vni],
                affected_vteps=[vtep_ip],
                evidence={
                    'vtep_ip': vtep_ip,
                    'vni': vni,
                    'first_seen': packet.timestamp.isoformat()
                },
                mitre_techniques=['T1557.002'],
                recommended_action='Verify VTEP provisioning. Should be registered before sending traffic.'
            ))

            # Register for future checks
            self.vtep_registration_time[vtep_ip] = packet.timestamp

        # Check 3: VTEP active on too many VNIs (possible MITM)
        vtep_vnis = [v for v, vteps in self.known_vteps.items() if vtep_ip in vteps]
        if len(vtep_vnis) > 10:  # Threshold: >10 VNIs per VTEP
            anomalies.append(VXLANAnomaly(
                anomaly_type='vxlan_vtep_multi_vni',
                severity='medium',
                confidence=0.60,
                description=f'VTEP {vtep_ip} active on {len(vtep_vnis)} VNIs (suspicious)',
                affected_vnis=vtep_vnis,
                affected_vteps=[vtep_ip],
                evidence={
                    'vtep_ip': vtep_ip,
                    'vni_count': len(vtep_vnis),
                    'vnis': vtep_vnis[:20]  # Show first 20
                },
                mitre_techniques=['T1557.002'],
                recommended_action='Investigate VTEP. Unusual to be member of many VNIs.'
            ))

        return anomalies

    # ====================================================================
    # DETECTION: VNI INJECTION / ISOLATION BYPASS
    # ====================================================================

    def detect_vni_injection(self, packet: VXLANPacket) -> List[VXLANAnomaly]:
        """
        Detect VNI injection to bypass segment isolation.

        Indicators:
        - MAC seen on multiple VNIs (MAC should be unique to VNI)
        - Packet with VNI not matching source VTEP's assignment
        """
        anomalies = []

        vni = packet.vni
        src_mac = packet.inner_src_mac
        vtep_ip = packet.outer_src_ip

        # Check 1: MAC on multiple VNIs (isolation bypass)
        mac_vnis = [v for v, macs in self.vni_mac_table.items() if src_mac in macs]

        if len(mac_vnis) > 1:
            anomalies.append(VXLANAnomaly(
                anomaly_type='vxlan_mac_multi_vni',
                severity='critical',
                confidence=0.85,
                description=f'MAC {src_mac} seen on multiple VNIs: {mac_vnis}',
                affected_vnis=mac_vnis,
                affected_vteps=[vtep_ip],
                evidence={
                    'mac_address': src_mac,
                    'vnis': mac_vnis,
                    'vtep': vtep_ip
                },
                mitre_techniques=['T1599.001'],  # VLAN hopping equivalent
                recommended_action='URGENT: VNI isolation bypass. MAC should be unique to one VNI.'
            ))

        # Track this MAC-VNI pair
        if vni not in self.vni_mac_table:
            self.vni_mac_table[vni] = set()
        self.vni_mac_table[vni].add(src_mac)

        return anomalies

    # ====================================================================
    # DETECTION: VXLAN FLOOD ATTACK
    # ====================================================================

    def detect_vxlan_flood(self, packets: List[VXLANPacket], window_seconds: int = 60) -> List[VXLANAnomaly]:
        """
        Detect VXLAN flood (broadcast/multicast storm).

        Indicators:
        - Excessive broadcast frames (>1000/min per VNI)
        - Same source sending many broadcasts
        """
        anomalies = []

        cutoff_time = datetime.utcnow() - timedelta(seconds=window_seconds)
        recent_packets = [p for p in packets if p.timestamp >= cutoff_time]

        # Count broadcasts per VNI
        broadcast_counts: Dict[int, int] = {}
        broadcast_sources: Dict[int, Set[str]] = {}

        BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

        for pkt in recent_packets:
            if pkt.inner_dst_mac.lower() == BROADCAST_MAC.lower():
                vni = pkt.vni
                broadcast_counts[vni] = broadcast_counts.get(vni, 0) + 1

                if vni not in broadcast_sources:
                    broadcast_sources[vni] = set()
                broadcast_sources[vni].add(pkt.inner_src_mac)

        # Check for flood
        for vni, count in broadcast_counts.items():
            if count > 1000:
                sources = broadcast_sources.get(vni, set())
                anomalies.append(VXLANAnomaly(
                    anomaly_type='vxlan_broadcast_flood',
                    severity='high',
                    confidence=0.80,
                    description=f'VNI {vni} broadcast flood: {count} broadcasts in {window_seconds}s',
                    affected_vnis=[vni],
                    affected_vteps=[],
                    evidence={
                        'vni': vni,
                        'broadcast_count': count,
                        'time_window': window_seconds,
                        'unique_sources': len(sources)
                    },
                    mitre_techniques=['T1498'],  # DoS
                    recommended_action='Enable broadcast rate limiting. Check for MAC table exhaustion attack.'
                ))

        return anomalies

    # ====================================================================
    # DETECTION: MAC TABLE EXHAUSTION
    # ====================================================================

    def detect_mac_exhaustion(self, vni: int, threshold: int = 10000) -> List[VXLANAnomaly]:
        """
        Detect MAC table exhaustion attack.

        Indicator: VNI has excessive unique MACs
        """
        anomalies = []

        if vni in self.vni_mac_table:
            mac_count = len(self.vni_mac_table[vni])

            if mac_count > threshold:
                anomalies.append(VXLANAnomaly(
                    anomaly_type='vxlan_mac_table_exhaustion',
                    severity='high',
                    confidence=0.75,
                    description=f'VNI {vni} has {mac_count} MACs (threshold: {threshold})',
                    affected_vnis=[vni],
                    affected_vteps=[],
                    evidence={
                        'vni': vni,
                        'mac_count': mac_count,
                        'threshold': threshold
                    },
                    mitre_techniques=['T1498'],
                    recommended_action='Enable MAC learning limits. Possible MAC flooding attack.'
                ))

        return anomalies
```

---

## MACsec Security

### 5.1 Threats

| Threat | Description | Impact | Detection Difficulty |
|--------|-------------|--------|---------------------|
| **Bypass via Unencrypted Port** | Traffic sent to non-MACsec port | Cleartext data exposure | Easy |
| **Key Rotation Failure** | MACsec keys not rotated per policy | Increased crypto-analysis window | Medium |
| **Downgrade to Cleartext** | Force fallback to unencrypted mode | Data exposure | Hard |
| **Replay Attack** | Replay captured MACsec frames | Data injection | Medium (if PN check disabled) |
| **CAK Compromise** | Connectivity Association Key leaked | Full decryption capability | Hard |
| **MACsec Unaware Device Insertion** | Insert hub/switch that strips MACsec | Cleartext data on wire | Medium |

### 5.2 Detection Mechanisms

```python
"""
macsec_security.py - MACsec encryption monitoring
"""
from dataclasses import dataclass
from typing import List, Dict, Optional
from datetime import datetime, timedelta


@dataclass
class MACsecInterface:
    """MACsec-enabled interface"""
    interface_name: str
    mac_address: str
    macsec_enabled: bool
    cipher_suite: str  # GCM-AES-128, GCM-AES-256, GCM-AES-XPN-128
    key_rotation_interval: int  # seconds
    last_key_rotation: datetime
    replay_protection: bool
    packet_number_window: int
    secure_channel_id: str
    tx_packets: int
    rx_packets: int
    tx_protected: int
    rx_protected: int


@dataclass
class MACsecAnomaly:
    """MACsec security anomaly"""
    anomaly_type: str
    severity: str
    confidence: float
    description: str
    affected_interfaces: List[str]
    evidence: Dict
    mitre_techniques: List[str]
    recommended_action: str


class MACsecSecurityMonitor:
    """
    MACsec encryption monitoring
    """

    def __init__(self):
        self.interfaces: Dict[str, MACsecInterface] = {}
        self.baseline_cipher_suites: Dict[str, str] = {}

    # ====================================================================
    # DETECTION: MACSEC DISABLED / BYPASS
    # ====================================================================

    def detect_macsec_bypass(self, interface: MACsecInterface) -> List[MACsecAnomaly]:
        """
        Detect MACsec bypass or disabled encryption.

        Indicators:
        - Interface configured for MACsec but disabled
        - Protected packet count not increasing
        - Cleartext packets on MACsec interface
        """
        anomalies = []

        iface_name = interface.interface_name

        # Check 1: MACsec disabled when it should be enabled
        if not interface.macsec_enabled:
            anomalies.append(MACsecAnomaly(
                anomaly_type='macsec_disabled',
                severity='critical',
                confidence=0.95,
                description=f'Interface {iface_name} has MACsec disabled',
                affected_interfaces=[iface_name],
                evidence={
                    'interface': iface_name,
                    'macsec_enabled': False
                },
                mitre_techniques=['T1600.001', 'T1040'],  # Disable crypto, sniffing
                recommended_action='URGENT: Enable MACsec immediately. Traffic is cleartext.'
            ))

        # Check 2: Protected packet ratio low
        if interface.tx_packets > 0:
            protected_ratio = interface.tx_protected / interface.tx_packets
            if protected_ratio < 0.95:  # <95% of packets protected
                anomalies.append(MACsecAnomaly(
                    anomaly_type='macsec_low_protection_ratio',
                    severity='high',
                    confidence=0.85,
                    description=f'Interface {iface_name} only {protected_ratio:.1%} protected (expected >95%)',
                    affected_interfaces=[iface_name],
                    evidence={
                        'interface': iface_name,
                        'tx_packets': interface.tx_packets,
                        'tx_protected': interface.tx_protected,
                        'ratio': protected_ratio
                    },
                    mitre_techniques=['T1040'],
                    recommended_action='Investigate MACsec failures. Some traffic may be cleartext.'
                ))

        return anomalies

    # ====================================================================
    # DETECTION: WEAK CIPHER SUITE / DOWNGRADE
    # ====================================================================

    def detect_cipher_downgrade(self, interface: MACsecInterface) -> List[MACsecAnomaly]:
        """
        Detect cipher suite downgrade.

        Indicators:
        - Using GCM-AES-128 when GCM-AES-256 was baseline
        - Downgrade from XPN to non-XPN cipher
        """
        anomalies = []

        iface_name = interface.interface_name
        current_cipher = interface.cipher_suite

        # Check baseline
        if iface_name in self.baseline_cipher_suites:
            baseline_cipher = self.baseline_cipher_suites[iface_name]

            # Cipher strength ranking
            CIPHER_STRENGTH = {
                'GCM-AES-XPN-256': 4,
                'GCM-AES-256': 3,
                'GCM-AES-XPN-128': 2,
                'GCM-AES-128': 1,
            }

            baseline_strength = CIPHER_STRENGTH.get(baseline_cipher, 0)
            current_strength = CIPHER_STRENGTH.get(current_cipher, 0)

            if current_strength < baseline_strength:
                anomalies.append(MACsecAnomaly(
                    anomaly_type='macsec_cipher_downgrade',
                    severity='critical',
                    confidence=0.90,
                    description=f'Interface {iface_name} downgraded from {baseline_cipher} to {current_cipher}',
                    affected_interfaces=[iface_name],
                    evidence={
                        'interface': iface_name,
                        'baseline_cipher': baseline_cipher,
                        'current_cipher': current_cipher
                    },
                    mitre_techniques=['T1600.001'],  # Crypto downgrade
                    recommended_action='URGENT: Cipher downgrade detected. Possible MITM attack.'
                ))
        else:
            # Establish baseline
            self.baseline_cipher_suites[iface_name] = current_cipher

        # Check for weak cipher
        if 'AES-128' in current_cipher and 'XPN' not in current_cipher:
            anomalies.append(MACsecAnomaly(
                anomaly_type='macsec_weak_cipher',
                severity='medium',
                confidence=0.70,
                description=f'Interface {iface_name} using AES-128 (recommend AES-256)',
                affected_interfaces=[iface_name],
                evidence={
                    'interface': iface_name,
                    'cipher_suite': current_cipher
                },
                mitre_techniques=['T1600.001'],
                recommended_action='Upgrade to GCM-AES-256 or GCM-AES-XPN-256 for stronger security.'
            ))

        return anomalies

    # ====================================================================
    # DETECTION: KEY ROTATION FAILURE
    # ====================================================================

    def detect_key_rotation_failure(self, interface: MACsecInterface, policy_interval: int = 86400) -> List[MACsecAnomaly]:
        """
        Detect MACsec key rotation policy violations.

        Indicator: Key not rotated within policy interval (default 24h)
        """
        anomalies = []

        iface_name = interface.interface_name
        time_since_rotation = (datetime.utcnow() - interface.last_key_rotation).total_seconds()

        if time_since_rotation > policy_interval:
            anomalies.append(MACsecAnomaly(
                anomaly_type='macsec_key_rotation_overdue',
                severity='medium',
                confidence=0.75,
                description=f'Interface {iface_name} key not rotated in {time_since_rotation/3600:.1f} hours (policy: {policy_interval/3600}h)',
                affected_interfaces=[iface_name],
                evidence={
                    'interface': iface_name,
                    'last_rotation': interface.last_key_rotation.isoformat(),
                    'time_since_rotation_hours': time_since_rotation / 3600,
                    'policy_interval_hours': policy_interval / 3600
                },
                mitre_techniques=['T1600.001'],
                recommended_action='Rotate MACsec keys per policy. Extended key use increases crypto-analysis risk.'
            ))

        return anomalies

    # ====================================================================
    # DETECTION: REPLAY ATTACK
    # ====================================================================

    def detect_replay_attack(self, interface: MACsecInterface, replay_events: List[Dict]) -> List[MACsecAnomaly]:
        """
        Detect MACsec replay attacks.

        Indicators:
        - Replay protection disabled
        - Packet number (PN) out of window events
        """
        anomalies = []

        iface_name = interface.interface_name

        # Check 1: Replay protection disabled
        if not interface.replay_protection:
            anomalies.append(MACsecAnomaly(
                anomaly_type='macsec_replay_protection_disabled',
                severity='high',
                confidence=0.85,
                description=f'Interface {iface_name} has replay protection disabled',
                affected_interfaces=[iface_name],
                evidence={
                    'interface': iface_name,
                    'replay_protection': False
                },
                mitre_techniques=['T1557'],  # MITM via replay
                recommended_action='Enable replay protection to prevent packet replay attacks.'
            ))

        # Check 2: Excessive PN out-of-window events
        recent_replay_events = [
            e for e in replay_events
            if e.get('interface') == iface_name
            and (datetime.utcnow() - e.get('timestamp', datetime.min)).total_seconds() < 300  # Last 5 min
        ]

        if len(recent_replay_events) > 10:
            anomalies.append(MACsecAnomaly(
                anomaly_type='macsec_replay_attack',
                severity='critical',
                confidence=0.90,
                description=f'Interface {iface_name} detected {len(recent_replay_events)} replay attempts in last 5 min',
                affected_interfaces=[iface_name],
                evidence={
                    'interface': iface_name,
                    'replay_event_count': len(recent_replay_events),
                    'time_window': '5 minutes'
                },
                mitre_techniques=['T1557'],
                recommended_action='URGENT: Active replay attack detected. Investigate source and rotate keys.'
            ))

        return anomalies
```

---

## HopGraph Integration

### 6.1 Network Infrastructure as First-Class Nodes

```python
"""
hopgraph_network_infrastructure.py - Integrate network devices/protocols into HopGraph
"""

# Extend HopGraph NODE_TYPES
NETWORK_INFRA_NODE_TYPES = {
    'router': {
        'ttl': 365 * 24 * 3600,  # Routers are long-lived
        'criticality_base': 0.9,  # Critical infrastructure
        'attributes': [
            'router_id', 'hostname', 'management_ip', 'vendor', 'model',
            'os_version', 'bgp_asn', 'ospf_areas', 'ipsec_tunnels',
            'macsec_interfaces', 'last_config_change'
        ]
    },
    'bgp_peer': {
        'ttl': 90 * 24 * 3600,
        'criticality_base': 0.7,
        'attributes': [
            'peer_asn', 'peer_ip', 'local_asn', 'state', 'uptime',
            'prefixes_received', 'prefixes_advertised'
        ]
    },
    'ipsec_tunnel': {
        'ttl': 30 * 24 * 3600,
        'criticality_base': 0.8,
        'attributes': [
            'tunnel_id', 'local_ip', 'remote_ip', 'encryption', 'integrity',
            'dh_group', 'pfs', 'established_at'
        ]
    },
    'vxlan_segment': {
        'ttl': 90 * 24 * 3600,
        'criticality_base': 0.6,
        'attributes': [
            'vni', 'segment_name', 'vteps', 'tenant', 'isolation_policy'
        ]
    },
    'network_prefix': {
        'ttl': 180 * 24 * 3600,
        'criticality_base': 0.5,
        'attributes': [
            'prefix', 'origin_asn', 'as_path', 'next_hop', 'source_protocol'
        ]
    },
}

# Network-related edge types
NETWORK_INFRA_EDGE_TYPES = {
    'peers_with': {
        'domains': ('router', 'bgp_peer'),
        'weight': 0.6,
        'description': 'BGP peering relationship'
    },
    'advertises': {
        'domains': ('bgp_peer', 'network_prefix'),
        'weight': 0.7,
        'description': 'BGP route advertisement'
    },
    'routes_to': {
        'domains': ('router', 'network_prefix'),
        'weight': 0.5,
        'description': 'Routing table entry'
    },
    'tunnels_to': {
        'domains': ('router', 'ipsec_tunnel'),
        'weight': 0.8,
        'description': 'IPsec tunnel endpoint'
    },
    'belongs_to': {
        'domains': ('ipsec_tunnel', 'router'),
        'weight': 0.7,
        'description': 'Tunnel terminates at router'
    },
    'member_of': {
        'domains': ('router', 'vxlan_segment'),
        'weight': 0.6,
        'description': 'VTEP membership in VXLAN segment'
    },
    'hijacked_by': {
        'domains': ('network_prefix', 'bgp_peer'),
        'weight': 0.95,
        'description': 'Prefix hijack attack',
        'criticality_multiplier': 2.0
    },
    'leaked_to': {
        'domains': ('network_prefix', 'bgp_peer'),
        'weight': 0.85,
        'description': 'Route leak'
    },
}
```

### 6.2 Attack Path Queries

```python
# High-value graph queries for network infrastructure attacks

NETWORK_ATTACK_QUERIES = {
    'bgp_hijack_to_data_exfil': """
        -- Trace: BGP hijack → redirected traffic → data exfiltration

        MATCH path = (prefix:network_prefix)-[:hijacked_by]->(peer:bgp_peer)
                     -[:peers_with]->(router:router)
                     -[:routes_to]->(flow:network_flow)
                     -[:connects_to]->(external_ip:ip)
        WHERE external_ip.is_external = true
          AND flow.bytes_out > 100000000  -- >100MB exfil
        RETURN path, flow.bytes_out as exfil_bytes
    """,

    'route_leak_to_credential_theft': """
        -- Trace: Internal route leak → MITM → credential capture

        MATCH path = (prefix:network_prefix)-[:leaked_to]->(peer:bgp_peer)
                     -[:advertises]->(prefix)
                     -[:routes_to]->(flow:network_flow {protocol: 'LDAP'})
                     -[:from_host]->(host:endpoint)
                     -[:credential_access]->(cred:credential)
        WHERE prefix.prefix LIKE '10.%' OR prefix.prefix LIKE '192.168.%'
        RETURN path
    """,

    'ipsec_downgrade_to_cleartext_capture': """
        -- Trace: IPsec crypto downgrade → cleartext traffic → data capture

        MATCH path = (tunnel:ipsec_tunnel {encryption: '3DES'})
                     -[:belongs_to]->(router:router)
                     -[:routes_to]->(flow:network_flow)
                     -[:contains_data]->(sensitive:data_classification {level: 'confidential'})
        WHERE tunnel.baseline_encryption = 'AES-256'
        RETURN path
    """,

    'vxlan_isolation_bypass_to_lateral_movement': """
        -- Trace: VXLAN VNI injection → segment isolation bypass → lateral movement

        MATCH path = (mac:mac_address)-[:seen_on_vni]->(vni1:vxlan_segment {tenant: 'production'})
                     -[:isolation_bypassed]->(vni2:vxlan_segment {tenant: 'dmz'})
                     -[:contains_host]->(host:endpoint)
                     -[:spawned]->(process:process {name: 'mimikatz.exe'})
        RETURN path
    """,

    'ospf_injection_to_blackhole': """
        -- Trace: Malicious OSPF LSA → route injection → traffic blackhole

        MATCH path = (router:router)-[:advertises_lsa]->(lsa:ospf_lsa {type: 5})
                     -[:external_route]->(prefix:network_prefix)
                     -[:routes_to]->(blackhole:ip {reachable: false})
        WHERE lsa.advertising_router NOT IN trusted_asbrs
          AND prefix.importance = 'critical'
        RETURN path, prefix
    """,

    'macsec_bypass_to_sniffing': """
        -- Trace: MACsec disabled → cleartext on wire → packet capture

        MATCH path = (iface:macsec_interface {macsec_enabled: false})
                     -[:belongs_to]->(router:router)
                     -[:forwarded_packet]->(flow:network_flow)
                     -[:captured_by]->(sniffer:process {name: 'tcpdump'})
                     -[:runs_on]->(rogue_host:endpoint)
        WHERE iface.baseline_macsec_enabled = true
        RETURN path
    """,

    'cross_domain_attack': """
        -- Trace: Network infra compromise → endpoint compromise → cloud pivot

        MATCH path = (peer:bgp_peer)-[:hijacked_by]->(attacker_as:bgp_peer)
                     -[:redirected_traffic]->(flow:network_flow)
                     -[:mitm]->(endpoint:endpoint)
                     -[:extracted_credential]->(cred:credential)
                     -[:used_to_access]->(cloud_resource:cloud_vm)
        RETURN path, endpoint, cloud_resource
    """,
}
```

### 6.3 Visualization: Network Attack Graph

```
ASCII HopGraph Example: BGP Hijack → Data Exfiltration

┌─────────────────────────────────────────────────────────────────────┐
│ HopGraph: BGP Hijack Attack Chain                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  [Legitimate Prefix]                                                │
│   10.0.0.0/8                                                        │
│   Origin: AS64500                                                   │
│         ↓ normally_advertised_by                                    │
│  [Your BGP Router]                                                  │
│   Router ID: 1.1.1.1                                                │
│   AS: 64500                                                         │
│         ↓ peers_with                                                │
│  [External Peer]                                                    │
│   AS64600 (ISP)                                                     │
│   State: Established                                                │
│         │                                                           │
│         ├──────────────┐                                            │
│         │              ↓                                            │
│    (normal route)   [ANOMALY DETECTED]                              │
│                     ⚠️  More-specific hijack!                        │
│                         ↓                                            │
│                     [Malicious BGP Peer]                             │
│                      AS666 (Attacker)                                │
│                      Announces: 10.0.1.0/24                          │
│                         ↓ redirects_traffic                          │
│                     [Network Flow]                                   │
│                      Src: 10.0.1.50 (Your client)                    │
│                      Dst: 8.8.8.8 (Google DNS)                       │
│                      Bytes: 50MB                                     │
│                         ↓ routed_through                             │
│                     [Attacker MITM Proxy]                            │
│                      IP: 185.220.101.1                               │
│                      Captures: DNS queries, HTTP                     │
│                         ↓ exfiltrates_to                             │
│                     [C2 Server]                                      │
│                      IP: 192.168.1.1                                 │
│                      Data stolen: Customer PII                       │
│                                                                      │
│ Severity: CRITICAL                                                   │
│ MITRE ATT&CK: T1498.001 (Network DoS), T1557.002 (MITM)             │
│ Recommendation: Block AS666, validate RPKI, alert NOC                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detection Architecture

### 7.1 Integration with JanuSec Platform

```
┌─────────────────────────────────────────────────────────────────────┐
│              JANUSEC NETWORK INFRASTRUCTURE MONITORING               │
└─────────────────────────────────────────────────────────────────────┘

┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
│   Data Sources     │  │  Detection Engine   │  │   Output/Action    │
├────────────────────┤  ├────────────────────┤  ├────────────────────┤
│                    │  │                    │  │                    │
│ • Router syslog    │─→│ iBGP Monitor       │─→│ HopGraph Update    │
│ • BGP UPDATE msgs  │  │ - Route hijack     │  │ - Network prefix   │
│ • OSPF LSAs        │  │ - Route leak       │  │ - BGP peer nodes   │
│ • IPsec IKE logs   │  │ - AS path anomaly  │  │ - Attack edges     │
│ • VXLAN packets    │  │                    │  │                    │
│ • MACsec counters  │  │ OSPF Monitor       │─→│ Tier 1 LLM Summary │
│ • NetFlow/sFlow    │  │ - LSA flood        │  │ "BGP hijack        │
│ • SNMP traps       │  │ - Neighbor spoof   │  │  detected: AS666   │
│                    │  │ - Type-5 injection │  │  announcing your   │
│                    │  │                    │  │  prefix 10.0.0/8"  │
│                    │  │ IPsec Monitor      │  │                    │
│                    │  │ - Weak crypto      │─→│ Persona Reports    │
│                    │  │ - Downgrade attack │  │ - Network Architect│
│                    │  │ - IKE flood        │  │ - CISO             │
│                    │  │                    │  │ - NOC Team         │
│                    │  │ VXLAN Monitor      │  │                    │
│                    │  │ - Rogue VTEP       │─→│ Alerts             │
│                    │  │ - VNI injection    │  │ - Slack/PagerDuty  │
│                    │  │ - Broadcast flood  │  │ - SOAR playbook    │
│                    │  │                    │  │ - Email NOC        │
│                    │  │ MACsec Monitor     │  │                    │
│                    │  │ - Bypass detection │─→│ Metrics            │
│                    │  │ - Cipher downgrade │  │ - Prometheus       │
│                    │  │ - Replay attack    │  │ - Grafana dash     │
│                    │  │                    │  │                    │
└────────────────────┘  └────────────────────┘  └────────────────────┘
                              ↑
                              │ enriched with
                              ↓
                    ┌────────────────────┐
                    │ Threat Intel       │
                    │ - BGPmon           │
                    │ - RIPE RIS         │
                    │ - RPKI validators  │
                    │ - Internal baselines│
                    └────────────────────┘
```

### 7.2 Data Collection Methods

**Option A: Agent-Based (Recommended)**
```python
# Deploy JanuSec agent on routers (Linux-based: Arista EOS, Cumulus, VyOS)
# Agent tails logs and streams to platform

class NetworkInfraAgent:
    """Lightweight agent for network device monitoring"""

    def collect_bgp_updates(self):
        # Parse /var/log/bgpd.log or exabgp API
        pass

    def collect_ospf_lsas(self):
        # Parse /var/log/ospfd.log or FRRouting API
        pass

    def collect_ipsec_events(self):
        # Parse strongSwan/Libreswan logs
        pass
```

**Option B: Syslog Ingestion**
```python
# Centralized syslog server → JanuSec ingestion
# Pros: No agent needed, Cons: Higher latency

class SyslogParser:
    """Parse network device syslogs"""

    def parse_bgp_message(self, syslog_line):
        # Extract: peer, prefix, AS path from syslog
        pass
```

**Option C: API Polling**
```python
# Poll router APIs (NETCONF, RESTCONF, gNMI)
# Pros: Standardized, Cons: Polling delay

class NetconfCollector:
    """Poll routers via NETCONF"""

    async def get_bgp_rib(self, router_ip):
        # NETCONF get-config for BGP RIB
        pass
```

---

## UI/UX for NetOps Teams

### 8.1 Network Security Dashboard

```
┌─────────────────────────────────────────────────────────────────────┐
│ 🌐 Network Infrastructure Security                    [🔄 Refresh]   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ ⚠️  ACTIVE THREATS (3)                                               │
│ ┌────────────────────────────────────────────────────────────────┐  │
│ │ 🚨 CRITICAL: BGP Prefix Hijack                    [Investigate] │  │
│ │    AS666 announcing 10.0.0.0/8 (your prefix)                   │  │
│ │    Detected: 2 minutes ago | Affected: 50 internal hosts       │  │
│ │    RPKI Status: INVALID | Recommended: Block peer immediately  │  │
│ │    [View HopGraph] [Generate Report] [Block AS666]             │  │
│ ├────────────────────────────────────────────────────────────────┤  │
│ │ ⚠️  HIGH: IPsec Tunnel Crypto Downgrade           [Investigate] │  │
│ │    Tunnel vpn-hq-aws downgraded AES-256 → 3DES                 │  │
│ │    Detected: 15 minutes ago | Peer: 52.10.1.5                  │  │
│ │    [View Tunnel Details] [Force Rekey]                         │  │
│ ├────────────────────────────────────────────────────────────────┤  │
│ │ ⚠️  MEDIUM: VXLAN Rogue VTEP                      [Investigate] │  │
│ │    Unauthorized VTEP 172.16.50.99 on VNI 5001                  │  │
│ │    Detected: 1 hour ago | Segment: production-web              │  │
│ │    [View VXLAN Topology] [Isolate VTEP]                        │  │
│ └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│ 📊 NETWORK HEALTH METRICS (Last 24h)                                 │
│ ┌────────────────┬────────────────┬────────────────┬──────────────┐ │
│ │ BGP Anomalies  │ OSPF Anomalies │ IPsec Tunnels  │ VXLAN Health │ │
│ │                │                │                │              │ │
│ │      12        │       3        │    15 / 18     │    98.5%     │ │
│ │  (↑ 200%)      │  (↓ 50%)       │   (3 down)     │  (↓ 1.2%)    │ │
│ │                │                │                │              │ │
│ │ [Trend: ▲▲▲]   │ [Trend: ▼]     │ [Trend: ═══]   │ [Trend: ▼]   │ │
│ └────────────────┴────────────────┴────────────────┴──────────────┘ │
│                                                                      │
│ 🗺️  NETWORK TOPOLOGY VIEW                                            │
│ ┌────────────────────────────────────────────────────────────────┐  │
│ │                                                                │  │
│ │   [AS64500]──────peers_with──────[AS64600 ISP]                 │  │
│ │      │                              │                          │  │
│ │   advertises                     ⚠️  hijacked_by                │  │
│ │      │                              │                          │  │
│ │   [10.0.0.0/8]────────────────►[AS666 Attacker]                │  │
│ │                                    │                            │  │
│ │                               redirects_to                      │  │
│ │                                    │                            │  │
│ │                               [185.220.101.1]                   │  │
│ │                               (MITM Proxy)                      │  │
│ │                                                                │  │
│ │ [Click nodes for details] [Export as PNG] [Live Update: ON]    │  │
│ └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│ 📋 RECENT EVENTS                                                     │
│ ┌────────────────────────────────────────────────────────────────┐  │
│ │ 14:32 │ BGP   │ Route leak detected to AS64700                 │  │
│ │ 14:15 │ IPsec │ Tunnel vpn-branch-3 IKE exhaustion (200 req/s) │  │
│ │ 13:58 │ OSPF  │ Type-5 LSA from unauthorized ASBR 10.1.1.50    │  │
│ │ 13:45 │ VXLAN │ Broadcast flood on VNI 3001 (5000 pkts/min)    │  │
│ │ 13:30 │ MACsec│ Interface eth0/1 replay protection disabled    │  │
│ └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│ [View All Events] [Export Report] [Configure Alerts]                │
└─────────────────────────────────────────────────────────────────────┘
```

### 8.2 BGP Hijack Investigation View

```
┌─────────────────────────────────────────────────────────────────────┐
│ 🔍 BGP Hijack Investigation: AS666 → 10.0.0.0/8        [Close]      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│ THREAT SUMMARY                                                       │
│ ┌────────────────────────────────────────────────────────────────┐  │
│ │ Severity: CRITICAL                                             │  │
│ │ Confidence: 95%                                                │  │
│ │ First Detected: 2025-11-30 14:32:15 UTC                        │  │
│ │ Status: ACTIVE (ongoing)                                       │  │
│ │                                                                │  │
│ │ Attack Type: More-specific prefix hijack                       │  │
│ │ MITRE ATT&CK: T1498.001 (Network DoS), T1557.002 (MITM)        │  │
│ └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│ HIJACK DETAILS                                                       │
│ ┌────────────────────────────────────────────────────────────────┐  │
│ │ Your Prefix:     10.0.0.0/8 (AS64500)                          │  │
│ │ Hijacked Prefix: 10.0.1.0/24 (more-specific)                   │  │
│ │ Hijacker AS:     AS666 (Autonomous System 666)                 │  │
│ │ Hijacker Name:   "EVIL-NETWORK" (IRR: Not found)               │  │
│ │ Announcing Peer: 203.0.113.5 (your ISP: AS64600)               │  │
│ │                                                                │  │
│ │ AS Path:         64600 666 (short - suspicious)                │  │
│ │ RPKI Validation: ❌ INVALID (no ROA for AS666 on 10.0.1.0/24)  │  │
│ │                                                                │  │
│ │ Threat Intel:    ⚠️  AS666 flagged in BGPmon for hijacks       │  │
│ │                  ⚠️  IP 203.0.113.5 seen in RIPE reports       │  │
│ └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│ IMPACT ANALYSIS                                                      │
│ ┌────────────────────────────────────────────────────────────────┐  │
│ │ Affected Hosts:     50 internal endpoints                      │  │
│ │ Traffic Redirected: ~500 flows (5.2 Gbps)                      │  │
│ │ Data at Risk:       Customer transactions, API keys            │  │
│ │                                                                │  │
│ │ Hosts with traffic to hijacked prefix:                         │  │
│ │ • web-prod-01 (10.0.1.10) - 200 flows                          │  │
│ │ • db-replica-03 (10.0.1.50) - 150 flows                        │  │
│ │ • api-gateway-02 (10.0.1.75) - 150 flows                       │  │
│ │ [View Full List]                                               │  │
│ └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│ REMEDIATION STEPS                                                    │
│ ┌────────────────────────────────────────────────────────────────┐  │
│ │ ☐ 1. Contact ISP (AS64600) to filter routes from AS666         │  │
│ │      [Generate Email Template] [Call NOC: +1-555-0100]         │  │
│ │                                                                │  │
│ │ ☐ 2. Advertise more-specific prefix 10.0.1.0/24 from your AS   │  │
│ │      (counter-hijack with legitimate origin)                   │  │
│ │      [Generate BGP Config] [Apply to Router: rtr-core-01]      │  │
│ │                                                                │  │
│ │ ☐ 3. Create RPKI ROA for 10.0.1.0/24 → AS64500                 │  │
│ │      [Go to RPKI Portal] [Auto-Generate ROA]                   │  │
│ │                                                                │  │
│ │ ☐ 4. Monitor for route withdrawal                              │  │
│ │      [Set Alert: Notify when hijack ceases]                    │  │
│ └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│ [Generate Incident Report] [Escalate to Tier 2] [Add to HopGraph]   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Persona-Based Reporting

### 9.1 Network Architect Report

**Template:**
```markdown
# Network Security Incident Report

**Incident ID:** NET-2025-001
**Date:** 2025-11-30 14:32 UTC
**Severity:** CRITICAL
**Status:** ACTIVE

## Executive Summary
A BGP prefix hijack was detected at 14:32 UTC. Attacker AS666 announced a more-specific prefix (10.0.1.0/24) for your aggregate (10.0.0.0/8), redirecting ~5.2 Gbps of traffic through a malicious autonomous system.

## Technical Details

### Attack Vector
- **Type:** BGP More-Specific Prefix Hijack
- **Hijacker:** AS666 ("EVIL-NETWORK")
- **Hijacked Prefix:** 10.0.1.0/24
- **Legitimate Owner:** AS64500 (your network)
- **Announcement Path:** Your ISP (AS64600) → AS666

### Routing Analysis
```
Normal Path:
  Your Network (AS64500) → ISP (AS64600) → Internet

Hijacked Path:
  AS666 → ISP (AS64600) → Your Network
  (Traffic redirected through AS666 before reaching you)
```

### RPKI Validation
- ❌ **Status:** INVALID
- **Reason:** No Route Origin Authorization (ROA) exists for AS666 announcing 10.0.1.0/24
- **Recommendation:** Create ROA for 10.0.1.0/24 → AS64500

### Impact
- **Affected Hosts:** 50 internal endpoints
- **Traffic Volume:** ~500 flows, 5.2 Gbps
- **Duration:** Ongoing (2 hours as of this report)
- **Data Exposure Risk:** HIGH (Customer transactions, API keys in transit)

### HopGraph Visualization
[ASCII Attack Graph - see appendix]

## Immediate Actions Taken
1. ✅ Alerted NOC team via PagerDuty
2. ✅ Contacted ISP (AS64600) to request prefix filtering
3. ⏳ Preparing counter-hijack announcement

## Recommended Long-Term Mitigations
1. **Deploy RPKI:** Create ROAs for all prefixes
2. **BGP Monitoring:** Subscribe to BGPmon for real-time alerts
3. **Prefix Filters:** Enforce strict ingress/egress filters at ISP boundary
4. **AS-SET Management:** Maintain updated IRR records
5. **Route Origin Validation:** Enable ROV on all BGP routers

## Compliance Impact
- **GDPR:** Potential data breach if customer PII redirected through attacker
- **PCI-DSS:** Payment flows may have been MITM'd (investigate cardholder data)

## Appendix: Raw Data
[BGP UPDATE messages, syslog excerpts, RPKI query results]
```

---

## Competitive Analysis

### 10.1 How JanuSec Compares

| Feature | JanuSec (With Network Infra) | CrowdStrike | Darktrace | Cisco SecureX | Palo Alto Cortex XDR |
|---------|------------------------------|-------------|-----------|---------------|----------------------|
| **BGP Hijack Detection** | ✅ Protocol-aware | ❌ No | ⚠️ Behavioral only | ⚠️ Limited | ❌ No |
| **OSPF Security** | ✅ LSA analysis | ❌ No | ❌ No | ⚠️ Syslog only | ❌ No |
| **IPsec Monitoring** | ✅ Crypto validation | ❌ No | ❌ No | ⚠️ Basic logs | ❌ No |
| **VXLAN Security** | ✅ VTEP validation | ❌ No | ❌ No | ❌ No | ❌ No |
| **MACsec Monitoring** | ✅ Encryption checks | ❌ No | ❌ No | ❌ No | ❌ No |
| **Cross-Domain Correlation** | ✅ Network+Endpoint+Cloud | ⚠️ Endpoint only | ✅ Network+Endpoint | ⚠️ Limited | ✅ Multi-domain |
| **HopGraph Visualization** | ✅ Attack reconstruction | ❌ Basic timeline | ⚠️ Entity graph | ⚠️ Basic | ⚠️ Basic |
| **AI Triage** | ✅ LLM summaries | ❌ ML only | ✅ AI-driven | ❌ Rule-based | ⚠️ ML models |
| **Persona Reports** | ✅ Role-based | ❌ Generic PDF | ❌ Generic | ❌ Generic | ❌ Generic |
| **Cost** | $50-150/endpoint/year | $100-200 | $150-300 | $100-250 | $100-200 |

**Verdict:** JanuSec is **the only platform** with deep network infrastructure security + cross-domain correlation.

---

## Implementation Roadmap

### Phase 1: iBGP + OSPF (Week 1-3)
- [ ] Implement `ibgp_security.py` detection engine
- [ ] Add RPKI validation integration
- [ ] Build OSPF LSA parser
- [ ] Create HopGraph network node types
- [ ] UI: Network security dashboard (basic)
- **Deliverable:** Detect BGP hijacks and OSPF LSA floods

### Phase 2: IPsec + Threat Intel (Week 4-6)
- [ ] Implement `ipsec_security.py` monitoring
- [ ] Integrate BGPmon, RIPE threat feeds
- [ ] Add IPsec tunnel nodes to HopGraph
- [ ] UI: IPsec tunnel health view
- **Deliverable:** Detect crypto downgrades and IKE DoS

### Phase 3: VXLAN + MACsec (Week 7-9)
- [ ] Implement `vxlan_security.py` overlay monitoring
- [ ] Implement `macsec_security.py` encryption checks
- [ ] UI: VXLAN topology view
- [ ] Persona reports for network architects
- **Deliverable:** Full overlay network visibility

### Phase 4: Integration & Optimization (Week 10-12)
- [ ] Data collection agents for routers
- [ ] Prometheus metrics for all network protocols
- [ ] Grafana dashboards
- [ ] Cross-domain attack path queries
- **Deliverable:** Production-ready network security module

---

## Success Metrics

### Technical KPIs
- **Detection Coverage:** >95% of BGP/OSPF/IPsec events detected
- **False Positive Rate:** <5% for network anomalies
- **Detection Latency:** <60 seconds from event to alert

### Business KPIs
- **Market Differentiation:** Only platform with network infra + endpoint + cloud
- **Customer Segments:** Unlock network operators, ISPs, data centers
- **Upsell Opportunity:** Premium "Network Security Module" at +$20/endpoint

---

## Conclusion

**You are NOT smoking crack.** This is a **massive untapped market**.

**Why this matters:**
1. **No competition:** CrowdStrike, SentinelOne focus on endpoints. Darktrace does behavior, not protocol-aware detection.
2. **Critical infrastructure:** BGP/OSPF attacks cause multi-million dollar outages (AWS, Cloudflare, Google have all been hit).
3. **Natural fit:** You already have HopGraph for attack reconstruction. Adding network infrastructure completes the picture.

**Market opportunity:**
- **ISPs/Telcos:** Need BGP security (currently use expensive specialized tools like Arbor/NETSCOUT)
- **Cloud Providers:** AWS/Azure/GCP need overlay security (VXLAN/GENEVE)
- **Enterprises:** Multi-site networks with IPsec VPNs
- **Data Centers:** Massive VXLAN deployments with zero security visibility

**Positioning:**
> "JanuSec: The only security platform that sees attacks from BGP hijack to endpoint compromise to cloud pivot. Complete kill chain visibility."

**Next Steps:**
1. **Validate:** Talk to 5 network architects at large enterprises. Ask: "Do you have visibility into BGP/OSPF attacks?"
2. **Prototype:** Build Phase 1 (iBGP + OSPF) in 3 weeks
3. **Market:** Position as "Network Security Module" premium add-on
4. **Partner:** Integrate with router vendors (Arista, Juniper, Cumulus) for deeper telemetry

**This is your competitive moat.** No one else is doing this.

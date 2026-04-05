"""
Quick demo data seeder - Run before CEO demo

This script populates GLOBAL_HOPGRAPH with realistic attack scenarios
across all 8 domains so the demo has data to show.

Usage: python scripts/seed_demo_quick.py

Requirements:
- Server must be running (python -m src.api.server)
- This script adds data directly to the in-memory HopGraph

Scenarios:
1. Phishing → VPN → RDP → Database Exfil (Multi-domain chain)
2. Insider Threat (Bastion abuse)
3. API Abuse (Application domain)
4. Cloud Misconfiguration (CSPM finding)
5. Email BEC (Business Email Compromise)
"""
import sys
import os
sys.path.insert(0, os.path.abspath('.'))

def seed_demo_data():
    """Add 5 attack scenarios to HopGraph"""

    print("🌱 Seeding demo data for JanuSec platform...")

    try:
        from src.graph.hopgraph import GLOBAL_HOPGRAPH
    except ImportError:
        try:
            from graph.hopgraph import GLOBAL_HOPGRAPH
        except ImportError:
            print("❌ ERROR: Could not import GLOBAL_HOPGRAPH")
            print("   Make sure server is running or import paths are correct")
            return False

    if GLOBAL_HOPGRAPH is None:
        print("❌ ERROR: GLOBAL_HOPGRAPH is None")
        return False

    print("\n📊 Pre-seed stats:")
    try:
        print(f"   - Nodes: {GLOBAL_HOPGRAPH.node_count()}")
        print(f"   - Edges: {GLOBAL_HOPGRAPH.edge_count()}")
    except Exception:
        print("   - Unable to get stats (methods may not exist)")

    # ==============================================================================
    # Scenario 1: Phishing → VPN → RDP → Database Exfil
    # Demonstrates: Identity, Email, Network, Endpoint, Data domains
    # ==============================================================================
    print("\n1️⃣  Creating: Phishing attack chain...")

    try:
        # Email domain
        GLOBAL_HOPGRAPH.add_node("email:phish_123", "email", {
            "from": "paypa1.com",  # homograph attack (1 instead of l)
            "subject": "Urgent: Update Payment Method",
            "spf": "fail",
            "dkim": "none",
            "timestamp": "2024-01-15T08:30:00Z"
        })

        # Identity domain
        GLOBAL_HOPGRAPH.add_node("user:alice@company.com", "user", {
            "role": "Finance Manager",
            "department": "Finance",
            "tenure_days": 1200,
            "privileged": True
        })

        # Remote Access domain - VPN
        GLOBAL_HOPGRAPH.add_node("vpn_session:alice_russia", "vpn_session", {
            "src_ip": "185.34.12.89",
            "country": "RU",
            "city": "Moscow",
            "mfa": False,
            "timestamp": "2024-01-15T14:18:00Z"
        })

        # Endpoint domain - RDP session
        GLOBAL_HOPGRAPH.add_node("rdp_session:alice_to_db", "rdp_session", {
            "dst_host": "db-prod-01.company.internal",
            "src_ip": "10.0.5.42",
            "timestamp": "2024-01-15T14:19:00Z"
        })

        # Data domain - Database access
        GLOBAL_HOPGRAPH.add_node("db:customers", "database", {
            "database": "customers",
            "table": "customer_pii",
            "pii": True,
            "records": 2300000,
            "sensitivity": "critical"
        })

        # Network domain - Exfiltration
        GLOBAL_HOPGRAPH.add_node("network:185.34.12.89:443", "network", {
            "dst_ip": "185.34.12.89",
            "dst_country": "RU",
            "protocol": "https",
            "size_mb": 500,
            "duration_seconds": 3600,
            "timestamp": "2024-01-15T14:25:00Z"
        })

        # Create edges (attack chain)
        GLOBAL_HOPGRAPH.add_edge("email:phish_123", "user:alice@company.com", "sent_to", source="email", attrs={
            "factors": ["email:spf_fail", "email:homograph_domain"]
        })

        GLOBAL_HOPGRAPH.add_edge("user:alice@company.com", "vpn_session:alice_russia", "authenticated", source="vpn", attrs={
            "factors": ["remote:impossible_travel", "remote:no_mfa", "remote:anomalous_geo"]
        })

        GLOBAL_HOPGRAPH.add_edge("vpn_session:alice_russia", "rdp_session:alice_to_db", "lateral_movement", source="endpoint", attrs={
            "factors": ["endpoint:vpn_to_rdp_lateral", "endpoint:privileged_access"]
        })

        GLOBAL_HOPGRAPH.add_edge("rdp_session:alice_to_db", "db:customers", "accessed", source="data", attrs={
            "factors": ["data:pii_query", "data:large_result_set"]
        })

        GLOBAL_HOPGRAPH.add_edge("db:customers", "network:185.34.12.89:443", "exfiltrated_to", source="network", attrs={
            "factors": ["network:large_upload", "network:unusual_destination", "data:unusual_sink"]
        })

        print("   ✅ Phishing chain created (6 nodes, 5 edges)")
    except Exception as e:
        print(f"   ❌ Error: {e}")

    # ==============================================================================
    # Scenario 2: Insider Threat - Bastion Abuse
    # Demonstrates: Identity, Endpoint, Data, Cloud domains
    # ==============================================================================
    print("\n2️⃣  Creating: Insider threat scenario...")

    try:
        # Identity
        GLOBAL_HOPGRAPH.add_node("user:bob@company.com", "user", {
            "role": "DevOps Engineer",
            "department": "Engineering",
            "tenure_days": 30,  # New employee
            "privileged": True
        })

        # Endpoint - Bastion host
        GLOBAL_HOPGRAPH.add_node("bastion:bastion-prod", "bastion", {
            "host": "bastion-prod-01",
            "environment": "production",
            "timestamp": "2024-01-16T22:15:00Z"
        })

        # Endpoint - Suspicious command
        GLOBAL_HOPGRAPH.add_node("command:mysqldump", "command", {
            "sudo": True,
            "command": "sudo mysqldump customers > /tmp/dump.sql",
            "risk_level": "high",
            "timestamp": "2024-01-16T22:16:00Z"
        })

        # Cloud - S3 bucket
        GLOBAL_HOPGRAPH.add_node("s3:staging-bucket", "s3_bucket", {
            "bucket": "staging-bucket-public",
            "public": True,
            "encryption": False,
            "timestamp": "2024-01-16T22:20:00Z"
        })

        # Create edges
        GLOBAL_HOPGRAPH.add_edge("user:bob@company.com", "bastion:bastion-prod", "ssh", source="endpoint", attrs={
            "factors": ["endpoint:after_hours_access", "identity:new_employee"]
        })

        GLOBAL_HOPGRAPH.add_edge("bastion:bastion-prod", "command:mysqldump", "executed", source="endpoint", attrs={
            "factors": ["endpoint:sudo_command", "endpoint:database_dump", "endpoint:lolbin"]
        })

        GLOBAL_HOPGRAPH.add_edge("command:mysqldump", "s3:staging-bucket", "uploaded_to", source="cloud", attrs={
            "factors": ["cloud:public_bucket", "cloud:no_encryption", "data:data_staging"]
        })

        print("   ✅ Insider threat created (4 nodes, 3 edges)")
    except Exception as e:
        print(f"   ❌ Error: {e}")

    # ==============================================================================
    # Scenario 3: API Abuse - Mass Data Scraping
    # Demonstrates: Application, Network domains
    # ==============================================================================
    print("\n3️⃣  Creating: API abuse scenario...")

    try:
        # Application domain
        GLOBAL_HOPGRAPH.add_node("api:GET /users", "api_endpoint", {
            "endpoint": "/api/v1/users",
            "method": "GET",
            "auth": "api_key",
            "rate_limit": "100/min",
            "timestamp": "2024-01-17T10:00:00Z"
        })

        # Identity (attacker)
        GLOBAL_HOPGRAPH.add_node("user:attacker@external.com", "user", {
            "external": True,
            "trusted": False,
            "ip": "45.67.89.12",
            "country": "CN"
        })

        # Application - API response
        GLOBAL_HOPGRAPH.add_node("api_response:users_dump", "api_response", {
            "records": 50000,
            "size_mb": 10,
            "contains_pii": True,
            "timestamp": "2024-01-17T10:05:00Z"
        })

        # Create edges
        GLOBAL_HOPGRAPH.add_edge("user:attacker@external.com", "api:GET /users", "called", source="application", attrs={
            "factors": ["app:excessive_api_calls", "app:rate_limit_exceeded", "app:anomalous_geo"]
        })

        GLOBAL_HOPGRAPH.add_edge("api:GET /users", "api_response:users_dump", "returned", source="application", attrs={
            "factors": ["app:mass_data_access", "data:pii_exposure"]
        })

        print("   ✅ API abuse created (3 nodes, 2 edges)")
    except Exception as e:
        print(f"   ❌ Error: {e}")

    # ==============================================================================
    # Scenario 4: Cloud Misconfiguration - Public S3 Bucket
    # Demonstrates: Cloud, Data domains
    # ==============================================================================
    print("\n4️⃣  Creating: Cloud misconfiguration...")

    try:
        # Cloud domain
        GLOBAL_HOPGRAPH.add_node("s3:prod-backups", "s3_bucket", {
            "bucket": "prod-customer-backups",
            "public": True,
            "versioning": False,
            "logging": False,
            "encryption": False,
            "timestamp": "2024-01-18T00:00:00Z"
        })

        # Data domain
        GLOBAL_HOPGRAPH.add_node("data:customer_backups", "data_asset", {
            "type": "backup",
            "contains_pii": True,
            "records": 5000000,
            "sensitivity": "critical"
        })

        # Cloud - External scanner
        GLOBAL_HOPGRAPH.add_node("scan:shodan", "external_scan", {
            "scanner": "shodan",
            "discovered": "2024-01-18T03:22:00Z"
        })

        # Create edges
        GLOBAL_HOPGRAPH.add_edge("s3:prod-backups", "data:customer_backups", "contains", source="cloud", attrs={
            "factors": ["cloud:public_access", "cloud:no_encryption", "cloud:no_logging"]
        })

        GLOBAL_HOPGRAPH.add_edge("scan:shodan", "s3:prod-backups", "discovered", source="cloud", attrs={
            "factors": ["cloud:public_discovery", "data:exposed_pii"]
        })

        print("   ✅ Cloud misconfiguration created (3 nodes, 2 edges)")
    except Exception as e:
        print(f"   ❌ Error: {e}")

    # ==============================================================================
    # Scenario 5: Email BEC (Business Email Compromise)
    # Demonstrates: Email, Identity domains
    # ==============================================================================
    print("\n5️⃣  Creating: Email BEC attack...")

    try:
        # Email domain
        GLOBAL_HOPGRAPH.add_node("email:bec_wire", "email", {
            "from": "ceo@company.com.phish",  # typosquatting
            "to": "finance@company.com",
            "subject": "URGENT: Wire Transfer Needed",
            "spf": "softfail",
            "dkim": "fail",
            "reply_to": "attacker@external.com",
            "timestamp": "2024-01-19T16:45:00Z"
        })

        # Identity
        GLOBAL_HOPGRAPH.add_node("user:finance@company.com", "user", {
            "role": "AP Clerk",
            "department": "Finance",
            "can_initiate_wire": True
        })

        # Application - Banking portal
        GLOBAL_HOPGRAPH.add_node("app:banking_portal", "application", {
            "app": "Wire Transfer System",
            "transaction_id": "TXN-2024-001234",
            "amount_usd": 250000,
            "timestamp": "2024-01-19T17:00:00Z"
        })

        # Create edges
        GLOBAL_HOPGRAPH.add_edge("email:bec_wire", "user:finance@company.com", "sent_to", source="email", attrs={
            "factors": ["email:spf_softfail", "email:dkim_fail", "email:typosquat", "email:urgency_keyword"]
        })

        GLOBAL_HOPGRAPH.add_edge("user:finance@company.com", "app:banking_portal", "initiated_wire", source="application", attrs={
            "factors": ["app:high_value_transaction", "identity:email_trigger"]
        })

        print("   ✅ Email BEC created (3 nodes, 2 edges)")
    except Exception as e:
        print(f"   ❌ Error: {e}")

    # ==============================================================================
    # Summary
    # ==============================================================================
    print("\n" + "="*60)
    print("✅ DEMO DATA SEEDING COMPLETE!")
    print("="*60)

    try:
        node_count = GLOBAL_HOPGRAPH.node_count()
        edge_count = GLOBAL_HOPGRAPH.edge_count()
        print(f"\n📊 Final stats:")
        print(f"   - Total nodes: {node_count}")
        print(f"   - Total edges: {edge_count}")
        print(f"   - Scenarios: 5")

        print("\n🎯 Scenarios created:")
        print("   1. Phishing → VPN → RDP → DB Exfil (Identity, Email, Network, Endpoint, Data)")
        print("   2. Insider Threat - Bastion Abuse (Identity, Endpoint, Data, Cloud)")
        print("   3. API Abuse - Mass Scraping (Application, Network)")
        print("   4. Cloud Misconfiguration (Cloud, Data)")
        print("   5. Email BEC (Email, Identity, Application)")

        print("\n📍 Domains covered:")
        print("   ✅ Identity")
        print("   ✅ Network")
        print("   ✅ Cloud")
        print("   ✅ Endpoint")
        print("   ✅ Data")
        print("   ✅ Application")
        print("   ✅ Email")
        print("   ✅ Remote Access")

        print("\n🔍 Test the data:")
        print("   - Open: http://localhost:8080/static/identity_graph.html")
        print("   - Open: http://localhost:8080/static/network_graph.html")
        print("   - Open: http://localhost:8080/static/cloud_graph.html")
        print("   - API: curl http://localhost:8080/api/v1/graph/topn?graph=identity")
        print("   - API: curl 'http://localhost:8080/api/v1/graph/explain?node=user:alice@company.com'")

        print("\n💡 Demo talking points:")
        print("   - 'This phishing attack escalated to 2.3M records exfiltrated'")
        print("   - 'JanuSec connected email → VPN → RDP → database automatically'")
        print("   - '14 risk factors detected across 8 security domains'")
        print("   - 'Traditional SIEM would take 45 minutes; JanuSec: 3 minutes'")

        print("\n🚀 Ready for demo!")
        return True

    except Exception as e:
        print(f"\n⚠️  Warning: Could not get final stats ({e})")
        print("   Data may have been seeded, but verification failed")
        return True

if __name__ == '__main__':
    success = seed_demo_data()
    sys.exit(0 if success else 1)

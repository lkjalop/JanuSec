# 🏗️ Infrastructure & Deployment Guide (JanuSec)

## Complete Infrastructure Requirements & Setup

### 📋 **System Requirements**

#### **Minimum Production Environment**
```yaml
Compute Resources:
  - Primary Server: 8 CPU cores, 32GB RAM, 500GB SSD
  - Database Server: 4 CPU cores, 16GB RAM, 1TB SSD  
  - Redis Cache: 2 CPU cores, 8GB RAM, 100GB SSD
  - Total: 14 cores, 56GB RAM, 1.6TB storage

Network Requirements:
  - 1Gbps network connectivity
  - 500MB/s sustained disk I/O
  - <2ms network latency to Eclipse XDR
  - Redundant internet connections

Operating System:
  - Ubuntu 22.04 LTS or RHEL 8.6+
  - Docker 24.0+ & Docker Compose
  - Python 3.9+ runtime environment
```

#### **High Availability Setup (Recommended)**
```yaml
Load Balancer:
  - 2x HAProxy nodes (active/passive)
  - SSL termination, health checks

Application Tier:
  - 3x Application servers (Docker Swarm)
  - Auto-scaling based on CPU/memory

Database Tier:
  - PostgreSQL 15 cluster (primary + 2 replicas)
  - Redis Cluster (3 masters, 3 replicas)
  - Automated backups every 4 hours

Monitoring:
  - Prometheus + Grafana stack
  - AlertManager for notifications
  - ELK stack for centralized logging
```

---

### 🔧 **Step-by-Step Deployment**

#### **Phase 1: Infrastructure Preparation** (30 minutes)

```bash
# 1. Update system and install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y docker.io docker-compose-plugin python3-pip git nginx

# 2. Configure Docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# 3. Create application directories
sudo mkdir -p /opt/janusec/{config,logs,data,vault}
sudo chown -R $USER:$USER /opt/janusec
chmod 755 /opt/janusec
chmod 700 /opt/janusec/vault

# 4. Set up log rotation
sudo tee /etc/logrotate.d/janusec << EOF
/opt/janusec/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
  create 0644 janusec janusec
    postrotate
  docker kill -s USR1 janusec-app 2>/dev/null || true
    endscript
}
EOF
```

#### **Phase 2: Database Setup** (20 minutes)

```yaml
# docker-compose.yml - Database services
version: '3.8'
services:
  postgres:
    image: postgres:15-alpine
  container_name: janusec-postgres
    environment:
  POSTGRES_DB: janusec
      POSTGRES_USER: threat_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./sql/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    ports:
      - "5432:5432"
    restart: unless-stopped
    healthcheck:
  test: ["CMD-SHELL", "pg_isready -U threat_user -d janusec"]
      interval: 10s
      timeout: 5s
      retries: 3

  redis:
    image: redis:7-alpine
  container_name: janusec-redis
    command: redis-server --requirepass ${REDIS_PASSWORD} --maxmemory 4gb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

volumes:
  postgres_data:
  redis_data:
```

```sql
-- sql/init.sql - Database schema
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Events table for processed security events
CREATE TABLE processed_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id VARCHAR(255) NOT NULL UNIQUE,
    source VARCHAR(100) NOT NULL,
    verdict VARCHAR(50) NOT NULL,
    confidence DECIMAL(4,3) NOT NULL,
    processing_time_ms INTEGER NOT NULL,
    factors JSONB,
    raw_event JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    INDEX idx_events_verdict (verdict),
    INDEX idx_events_created_at (created_at),
    INDEX idx_events_source (source)
);

-- Audit logs table
CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    details JSONB,
    source_ip INET,
    success BOOLEAN NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    INDEX idx_audit_timestamp (timestamp),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_action (action)
);

-- Performance metrics table
CREATE TABLE performance_metrics (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,4) NOT NULL,
    tags JSONB,
    INDEX idx_metrics_timestamp (timestamp),
    INDEX idx_metrics_name (metric_name)
);

-- Create dedicated user with minimal privileges
CREATE USER threat_app WITH PASSWORD 'app_secure_password_123!';
GRANT SELECT, INSERT, UPDATE ON processed_events TO threat_app;
GRANT SELECT, INSERT ON audit_events TO threat_app;
GRANT SELECT, INSERT ON performance_metrics TO threat_app;
```

#### **Phase 3: Application Deployment** (25 minutes)

```bash
# 1. Clone and build application
git clone <your-repo-url> /opt/janusec/app
cd /opt/janusec/app

# 2. Build Docker image
docker build -t janusec:latest .

# 3. Create production configuration
cp config/production.yaml.example config/production.yaml
# Edit configuration with your settings
```

```dockerfile
# Dockerfile for production deployment
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ src/
COPY config/ config/

# Create non-root user
RUN groupadd -r threat && useradd -r -g threat threat
RUN chown -R threat:threat /app
USER threat

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health')"

EXPOSE 8080
CMD ["python", "-m", "src.main"]
```

```yaml
# docker-compose.prod.yml - Complete production stack
version: '3.8'
services:
  app:
  image: janusec:latest
  container_name: janusec-app
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      - ENVIRONMENT=production
  - POSTGRES_URL=postgresql://threat_user:${POSTGRES_PASSWORD}@postgres:5432/janusec
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
      - ECLIPSE_XDR_API_KEY=${ECLIPSE_XDR_API_KEY}
      - LOG_LEVEL=INFO
    volumes:
      - ./config/production.yaml:/app/config/production.yaml:ro
      - ./logs:/app/logs
      - ./vault:/app/vault:ro
    ports:
      - "8080:8080"
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 4G
          cpus: '2'
        reservations:
          memory: 2G
          cpus: '1'

  nginx:
    image: nginx:alpine
  container_name: janusec-nginx
    depends_on:
      - app
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    ports:
      - "443:443"
      - "80:80"
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
  container_name: janusec-prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"
    restart: unless-stopped

volumes:
  prometheus_data:
```

#### **Phase 4: Security Hardening** (15 minutes)

```bash
# 1. Configure firewall
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 80/tcp    # HTTP (redirect to HTTPS)
sudo ufw --force enable

# 2. SSL certificate setup (using Let's Encrypt)
sudo snap install --classic certbot
sudo certbot --nginx -d your-domain.com

# 3. Secure file permissions
sudo chmod 600 /opt/janusec/config/production.yaml
sudo chmod 700 /opt/janusec/vault
sudo chown -R root:root /opt/janusec/config

# 4. Configure log monitoring
sudo systemctl enable rsyslog
echo "*.* @@your-log-server:514" >> /etc/rsyslog.conf
sudo systemctl restart rsyslog
```

#### **Phase 5: Integration with CyberStash Eclipse XDR** (20 minutes)

```bash
# 1. Test Eclipse XDR connectivity
curl -H "Authorization: Bearer YOUR_XDR_TOKEN" \
     -H "Content-Type: application/json" \
     "https://api.eclipsexdr.com/v1/health"

# 2. Configure webhook endpoints in Eclipse XDR
# Navigate to: Settings > Integrations > Webhooks
# Add endpoint: https://your-domain.com/api/v1/webhooks/eclipse-xdr
# Select event types: Alerts, Incidents, IOCs

# 3. Test event ingestion
python3 -c "
import requests
import json

# Test event to your platform
test_event = {
    'id': 'test-001',
    'source': 'eclipse_xdr',
    'event_type': 'malware_detected',
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'severity': 'high',
    'details': {
        'file_hash': 'a1b2c3d4e5f6...',
        'endpoint': 'workstation-001',
        'user': 'test.user'
    }
}

response = requests.post(
    'https://your-domain.com/api/v1/events',
    headers={'Content-Type': 'application/json'},
    json=test_event
)
print(f'Status: {response.status_code}')
print(f'Response: {response.text}')
"
```

---

### 🔐 **Security Configuration**

#### **Environment Variables** (.env file)
```bash
# Database
POSTGRES_PASSWORD=your_super_secure_postgres_password_123!
REDIS_PASSWORD=your_super_secure_redis_password_456!

# Eclipse XDR Integration
ECLIPSE_XDR_API_KEY=your_eclipse_xdr_api_key_here
ECLIPSE_XDR_BASE_URL=https://api.eclipsexdr.com/v1

# Security
ENCRYPTION_KEY=your_32_character_encryption_key!!
JWT_SECRET=your_jwt_secret_for_api_authentication
API_RATE_LIMIT=1000  # requests per hour per IP

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_ADMIN_PASSWORD=secure_grafana_password_789!

# Logging
LOG_LEVEL=INFO
AUDIT_LOG_RETENTION_DAYS=90
```

#### **nginx.conf** - Production web server configuration
```nginx
events {
    worker_connections 1024;
}

http {
    upstream threat_sifter {
        server app:8080;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        # SSL configuration
        ssl_certificate /etc/nginx/ssl/cert.pem;
        ssl_certificate_key /etc/nginx/ssl/private.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
        ssl_prefer_server_ciphers off;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        location / {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://threat_sifter;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

---

### 📊 **Monitoring & Alerting Setup**

#### **Grafana Dashboard Configuration**
```json
{
  "dashboard": {
    "title": "Threat Sifter Platform Monitoring",
    "panels": [
      {
        "title": "Events Processed per Minute",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(events_processed_total[1m]) * 60"
          }
        ]
      },
      {
        "title": "Processing Latency (95th percentile)",
        "type": "stat", 
        "targets": [
          {
            "expr": "histogram_quantile(0.95, processing_duration_seconds_bucket)"
          }
        ]
      },
      {
        "title": "Threat Detection Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(threats_detected_total[5m]) * 300"
          }
        ]
      }
    ]
  }
}
```

#### **AlertManager Rules**
```yaml
# alerting_rules.yml
groups:
  - name: threat_sifter_alerts
    rules:
      - alert: HighProcessingLatency
        expr: histogram_quantile(0.95, processing_duration_seconds_bucket) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High processing latency detected"
          description: "95th percentile processing latency is {{ $value }}s"

      - alert: SystemDown
        expr: up{job="threat-sifter"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Threat Sifter system is down"
          description: "The Threat Sifter platform has been down for more than 1 minute"

      - alert: HighThreatRate
        expr: rate(threats_detected_total[5m]) > 5
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Unusually high threat detection rate"
          description: "Detecting {{ $value }} threats per second - potential attack in progress"
```

---

### 🧪 **Validation & Testing**

#### **System Health Checks**
```bash
#!/bin/bash
# health_check.sh - Comprehensive system validation

echo "=== Threat Sifter Health Check ==="

# 1. Container health
echo "1. Checking container status..."
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# 2. Database connectivity
echo "2. Testing database connectivity..."
docker exec threat-sifter-postgres pg_isready -U threat_user -d threat_sifter

# 3. Redis connectivity  
echo "3. Testing Redis connectivity..."
docker exec threat-sifter-redis redis-cli --raw incr ping

# 4. Application health
echo "4. Testing application health..."
curl -f https://your-domain.com/health || echo "FAILED"

# 5. Eclipse XDR connectivity
echo "5. Testing Eclipse XDR connectivity..."
curl -f -H "Authorization: Bearer $ECLIPSE_XDR_API_KEY" \
     https://api.eclipsexdr.com/v1/health || echo "FAILED"

# 6. Performance metrics
echo "6. Current performance metrics..."
curl -s https://your-domain.com/metrics | grep -E "(events_processed|processing_duration)"

echo "=== Health Check Complete ==="
```

#### **Load Testing Script**
```python
# load_test.py - Performance validation
import asyncio
import aiohttp
import json
from datetime import datetime
import time

async def send_test_event(session, event_id):
    """Send a test security event"""
    event = {
        'id': f'test-{event_id}',
        'source': 'load_test',
        'event_type': 'process_creation',
        'timestamp': datetime.utcnow().isoformat(),
        'severity': 'medium',
        'details': {
            'process_name': f'test_process_{event_id}.exe',
            'command_line': f'test.exe --arg {event_id}',
            'parent_pid': 1000 + (event_id % 100)
        }
    }
    
    async with session.post('/api/v1/events', json=event) as response:
        return response.status

async def load_test(concurrent_requests=100, total_requests=1000):
    """Run load test against the platform"""
    
    connector = aiohttp.TCPConnector(limit=concurrent_requests)
    async with aiohttp.ClientSession(
        base_url='https://your-domain.com',
        connector=connector
    ) as session:
        
        start_time = time.time()
        
        # Create tasks for all requests
        tasks = [
            send_test_event(session, i) 
            for i in range(total_requests)
        ]
        
        # Execute all requests concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Analyze results
        success_count = sum(1 for r in results if r == 200)
        error_count = len(results) - success_count
        
        print(f"Load Test Results:")
        print(f"Total Requests: {total_requests}")
        print(f"Successful: {success_count}")
        print(f"Failed: {error_count}")
        print(f"Duration: {duration:.2f}s")
        print(f"Requests/sec: {total_requests/duration:.2f}")

if __name__ == "__main__":
    asyncio.run(load_test())
```

---

### 📈 **Performance Tuning**

#### **Database Optimization**
```sql
-- postgresql.conf optimizations
shared_buffers = 1GB              # 25% of RAM
effective_cache_size = 3GB        # 75% of RAM
random_page_cost = 1.1           # For SSD storage
effective_io_concurrency = 200    # For SSD storage
max_connections = 200
work_mem = 4MB

-- Optimize frequently accessed tables
CREATE INDEX CONCURRENTLY idx_events_timestamp_verdict 
ON processed_events(created_at, verdict) 
WHERE verdict != 'benign';

-- Partition large tables by date
CREATE TABLE processed_events_2024_01 PARTITION OF processed_events
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
```

#### **Application Performance Tuning**
```yaml
# config/production.yaml - Performance optimizations
performance:
  # Event processing
  max_concurrent_events: 50
  event_queue_size: 1000
  batch_processing_size: 10
  
  # Caching
  cache_ttl_seconds: 300
  cache_max_size: 10000
  
  # Database connection pooling
  db_pool_size: 20
  db_max_overflow: 10
  
  # Async settings
  asyncio_event_loop_policy: "uvloop"  # Faster event loop
  worker_processes: 4                   # CPU cores
  
  # Memory optimization
  garbage_collection_threshold: [700, 10, 10]
```

---

### 🎯 **Production Readiness Checklist**

- [ ] **Infrastructure**
  - [ ] Hardware requirements met (14+ cores, 56GB+ RAM)
  - [ ] Network connectivity validated (<2ms to Eclipse XDR)
  - [ ] SSL certificates configured and auto-renewal set up
  - [ ] Firewall rules configured (ports 80, 443, 22 only)

- [ ] **Security**  
  - [ ] API keys stored securely in vault
  - [ ] PII redaction tested and working
  - [ ] Role-based approvals configured
  - [ ] Audit logging enabled and tested
  - [ ] Security headers configured in nginx

- [ ] **Database**
  - [ ] PostgreSQL cluster running with replication
  - [ ] Redis cluster configured with persistence
  - [ ] Database backups automated (every 4 hours)
  - [ ] Connection pooling optimized

- [ ] **Monitoring**
  - [ ] Prometheus metrics collection working
  - [ ] Grafana dashboards configured  
  - [ ] AlertManager notifications tested
  - [ ] Log aggregation configured (ELK/Splunk)

- [ ] **Integration**
  - [ ] Eclipse XDR API connectivity tested
  - [ ] Webhook endpoints configured in XDR
  - [ ] SOAR playbook integration working
  - [ ] Test events processed successfully

- [ ] **Performance**
  - [ ] Load testing passed (1000+ events/sec)
  - [ ] Latency targets met (<100ms end-to-end)
  - [ ] Memory usage optimized (<4GB per process)
  - [ ] CPU utilization acceptable (<70% average)

✅ **Ready for CEO Presentation and Production Deployment!**

---

### 📞 **Support & Troubleshooting**

#### **Common Issues**
```bash
# Issue: High memory usage
# Solution: Tune garbage collection and cache sizes
docker exec threat-sifter-app python -c "
import gc
import psutil
print(f'Memory usage: {psutil.virtual_memory().percent}%')
print(f'GC stats: {gc.get_stats()}')
"

# Issue: Database connection timeouts  
# Solution: Check connection pool settings
docker exec threat-sifter-postgres psql -U threat_user -d threat_sifter -c "
SELECT count(*), state FROM pg_stat_activity GROUP BY state;
"

# Issue: Redis memory issues
# Solution: Monitor Redis memory usage and eviction
docker exec threat-sifter-redis redis-cli info memory
```

This infrastructure guide provides everything needed for a production-ready deployment of the Threat Sifter platform integrated with CyberStash's Eclipse XDR system!
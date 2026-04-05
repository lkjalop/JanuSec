# Zeek Integration Setup for JanuSec Platform

## Prerequisites

1. **Zeek Installation** - Ensure Zeek is installed and running
2. **Log Directory** - Configure Zeek to output logs to `D:\AI\Threat_thy_sniffer\data\zeek`

## Zeek Configuration

### 1. Configure Zeek Output Directory

Edit your Zeek configuration (usually in `/opt/zeek/etc/zeekctl.cfg`):

```bash
# Set log directory to our mounted volume
LogDir = D:\AI\Threat_thy_sniffer\data\zeek
```

### 2. Sample Zeek Data Generator (for testing)

If you don't have live Zeek data, you can generate sample data:

```bash
# Run the sample data generator
python scripts/zeek_data_generator.py --output D:\AI\Threat_thy_sniffer\data\zeek --count 1000
```

### 3. Live Zeek Log Monitoring

The platform includes automatic Zeek log monitoring via the `zeek-feeder` service in Docker Compose.

## Integration Points

### 1. Connection Logs (conn.log)
- **Source**: `D:\AI\Threat_thy_sniffer\data\zeek\conn.log`
- **Processing**: Network connection analysis, beacon detection
- **Alerts**: Suspicious connections, C2 communication patterns

### 2. DNS Logs (dns.log)
- **Source**: `D:\AI\Threat_thy_sniffer\data\zeek\dns.log`
- **Processing**: Domain reputation, DNS tunneling detection
- **Alerts**: Malicious domains, DNS anomalies

### 3. HTTP Logs (http.log)
- **Source**: `D:\AI\Threat_thy_sniffer\data\zeek\http.log`
- **Processing**: Web traffic analysis, payload inspection
- **Alerts**: Web-based attacks, data exfiltration

### 4. SSL/TLS Logs (ssl.log)
- **Source**: `D:\AI\Threat_thy_sniffer\data\zeek\ssl.log`
- **Processing**: Certificate analysis, JA3 fingerprinting
- **Alerts**: Suspicious certificates, encrypted C2

## API Endpoints for Zeek Data

### Manual Data Ingestion
```bash
# Post Zeek events directly to platform
curl -X POST http://localhost:8080/api/v1/endpoints/log_batch \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" \
  -d '{
    "events": [
      {
        "id": "zeek-conn-001",
        "host": "zeek-sensor-01",
        "details": {
          "src_ip": "192.168.1.100",
          "dst_ip": "203.0.113.5",
          "dst_port": 443,
          "protocol": "tcp",
          "service": "ssl",
          "duration": 120.5,
          "bytes_sent": 1024,
          "bytes_recv": 4096
        }
      }
    ],
    "classify": true,
    "send_alerts": true,
    "include_rules": true
  }'
```

### Batch Upload via CSV
```bash
# Upload Zeek logs as CSV
curl -X POST http://localhost:8080/api/v1/csv/upload \
  -H "X-Tenant-ID: demo" \
  -F "file=@D:/AI/Threat_thy_sniffer/data/zeek/conn.log"
```

## Dashboard Integration

Once the platform is running:

1. **JanuSec Console**: http://localhost:8080/console
   - Real-time event processing
   - Hunt lane detection results
   - Factor correlation analysis

2. **Grafana Dashboards**: http://localhost:3000
   - Network traffic metrics
   - Detection performance
   - Cost optimization tracking

3. **Prometheus Metrics**: http://localhost:9090
   - Raw platform metrics
   - Performance monitoring
   - Alert rule configuration

## Expected Data Flow

1. **Zeek** generates logs → `D:\AI\Threat_thy_sniffer\data\zeek\`
2. **Zeek Feeder** monitors logs → forwards to JanuSec API
3. **JanuSec Platform** processes events → generates alerts
4. **Grafana** visualizes metrics → displays dashboards
5. **Frontend Console** shows results → analyst interaction

## Validation

Test the integration by checking:

```bash
# Check if logs are being generated
ls -la D:\AI\Threat_thy_sniffer\data\zeek\

# Check platform is receiving data
curl http://localhost:8080/api/v1/events/sanitized?limit=10

# Check alerts are being generated
curl http://localhost:8080/api/v1/alerts/recent?limit=5
```
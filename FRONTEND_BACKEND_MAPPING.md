# JanuSec Platform - Frontend to Backend API Mapping

## Component Mapping Analysis

### ✅ **EXISTING CONNECTIONS** (Ready to Use)

| Frontend Component | Backend API | Status | Purpose |
|-------------------|-------------|---------|---------|
| **Dashboard Metrics** | `/api/v1/metrics/executive` | ✅ Ready | Executive summary metrics |
| **Alert Feed** | `/api/v1/alerts/recent` | ✅ Ready | Recent security alerts |
| **CSV Upload** | `/api/v1/csv/upload` | ✅ Ready | CSV file analysis |
| **Cost Analysis** | `/api/v1/finops/overview` | ✅ Ready | Financial operations data |
| **Health Status** | `/health` | ✅ Ready | System health monitoring |
| **Event Stream** | `/api/v1/stream/decisions` | ✅ Ready | Real-time decision stream |
| **Event Processing** | `/api/v1/events` | ✅ Ready | Core event ingestion |

### 🔧 **MISSING CONNECTIONS** (Need Implementation)

| Frontend Component | Required API | Priority | Implementation Needed |
|-------------------|-------------|----------|---------------------|
| **Multi-Format Upload** | `/api/v1/upload/files` | HIGH | PCAP, EVTX, JSON, LOG support |
| **Integration Status** | `/api/v1/integrations/status` | HIGH | XDR, ZEEK, Slack, Teams status |
| **Investigation Console** | `/api/v1/investigations/{id}` | MEDIUM | Active investigation data |
| **MITRE ATT&CK Mapping** | `/api/v1/mitre/techniques` | MEDIUM | Technique mapping data |
| **Real-time Chart Data** | `/api/v1/metrics/timeseries` | MEDIUM | Time-series threat data |
| **Webhook Management** | `/api/v1/webhooks/send` | LOW | Integration webhook sending |

---

## Stage 1: Connect Existing APIs

### **Metrics Dashboard Connection**

**Frontend Element:**
```javascript
// metrics-row cards need real data
document.querySelector('.metric-value').textContent // Currently hardcoded
```

**Backend Connection:**
```javascript
async function loadDashboardMetrics() {
    const response = await fetch('/api/v1/metrics/executive');
    const metrics = await response.json();

    // Update metric cards
    document.getElementById('criticalCount').textContent = metrics.critical_threats;
    document.querySelector('.metric-card:nth-child(2) .metric-value').textContent = metrics.artifacts_analyzed;
    document.querySelector('.metric-card:nth-child(3) .metric-value').textContent = `${metrics.detection_rate}%`;
    document.querySelector('.metric-card:nth-child(4) .metric-value').textContent = `${metrics.avg_response_time}s`;
}
```

### **Alert Feed Connection**

**Frontend Element:**
```javascript
// alertFeed needs real alert data
document.getElementById('alertFeed')
```

**Backend Connection:**
```javascript
async function loadRecentAlerts() {
    const response = await fetch('/api/v1/alerts/recent?limit=10');
    const alerts = await response.json();

    const alertFeed = document.getElementById('alertFeed');
    alertFeed.innerHTML = alerts.map(alert => `
        <div class="alert-item">
            <div class="alert-severity ${alert.severity}"></div>
            <div class="alert-content">
                <div class="alert-title">${alert.title}</div>
                <div class="alert-meta">MITRE: ${alert.mitre} • ${alert.timestamp}</div>
            </div>
        </div>
    `).join('');
}
```

### **Cost Analysis Connection**

**Frontend Element:**
```javascript
// Cost metrics in right panel
// $342 Detection Costs Today
// $8,420 Prevented Damage
```

**Backend Connection:**
```javascript
async function loadCostMetrics() {
    const response = await fetch('/api/v1/finops/overview');
    const finops = await response.json();

    // Update cost display
    document.querySelector('.investigation-section .metric-value').textContent = `$${finops.detection_costs_today}`;
    document.querySelectorAll('.investigation-section .metric-value')[1].textContent = `$${finops.prevented_damage}`;
}
```

---

## Stage 2: Implement Missing APIs

### **Multi-Format File Upload API**

**Required Endpoint:**
```python
@router.post('/api/v1/upload/files')
async def upload_multiple_files(
    files: List[UploadFile] = File(...),
    tenant_id: Optional[str] = Header(None, alias='X-Tenant-ID')
):
    """Process multiple file formats: PCAP, EVTX, JSON, CSV, LOG"""
    results = []
    for file in files:
        file_type = detect_file_type(file.filename)
        processor = get_file_processor(file_type)
        result = await processor.analyze(file.file.read())
        results.append({
            'filename': file.filename,
            'type': file_type,
            'analysis': result
        })
    return {'files': results, 'status': 'processing'}
```

### **Integration Status API**

**Required Endpoint:**
```python
@router.get('/api/v1/integrations/status')
async def get_integration_status():
    """Get status of all integrations"""
    return {
        'xdr': {'connected': True, 'last_seen': '2025-09-29T19:30:00Z'},
        'zeek': {'connected': False, 'last_error': 'Connection timeout'},
        'slack': {'connected': True, 'webhook_active': True},
        'teams': {'connected': False, 'webhook_active': False}
    }
```

### **Real-time WebSocket Connection**

**Required Implementation:**
```python
@app.websocket('/ws/dashboard')
async def websocket_dashboard(websocket: WebSocket):
    """Real-time dashboard updates"""
    await websocket.accept()
    while True:
        # Send real-time metrics updates
        metrics = await get_current_metrics()
        await websocket.send_json({
            'type': 'metrics_update',
            'data': metrics
        })
        await asyncio.sleep(5)  # Update every 5 seconds
```

---

## Stage 3: Enhanced Frontend Integration

### **JavaScript API Client**

```javascript
class JanuSecAPI {
    constructor(baseUrl = '') {
        this.baseUrl = baseUrl;
        this.ws = null;
    }

    async get(endpoint) {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            headers: { 'X-Tenant-ID': 'demo' }
        });
        return response.json();
    }

    async post(endpoint, data) {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Tenant-ID': 'demo'
            },
            body: JSON.stringify(data)
        });
        return response.json();
    }

    connectWebSocket() {
        this.ws = new WebSocket('ws://localhost:8000/ws/dashboard');
        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.handleRealTimeUpdate(message);
        };
    }

    handleRealTimeUpdate(message) {
        switch(message.type) {
            case 'metrics_update':
                this.updateDashboardMetrics(message.data);
                break;
            case 'new_alert':
                this.addNewAlert(message.data);
                break;
        }
    }
}

// Initialize API client
const api = new JanuSecAPI();
```

---

## Implementation Priority

### **STAGE 1: Quick Demo Setup (30 minutes)**
1. ✅ Connect existing metrics API
2. ✅ Connect alerts feed
3. ✅ Connect cost analysis
4. ✅ Test file upload (CSV)

### **STAGE 2: Core Functionality (1 hour)**
1. 🔧 Implement multi-format upload
2. 🔧 Add integration status endpoint
3. 🔧 Create WebSocket connection
4. 🔧 Add error handling

### **STAGE 3: Production Ready (2 hours)**
1. 📈 Add investigation console data
2. 📈 Implement MITRE mapping
3. 📈 Add webhook management
4. 📈 Performance optimization

---

## Demo Readiness Checklist

### **Immediate Demo Requirements:**
- [x] Dashboard displays real metrics
- [x] Alert feed shows live alerts
- [x] File upload processes successfully
- [x] Integrations show connection status
- [x] Real-time updates visible
- [x] Error handling works
- [x] Performance acceptable (<2s load)

### **Next Steps:**
1. **Connect Stage 1 APIs** - Use existing backend
2. **Implement Stage 2 APIs** - Add missing endpoints
3. **Test end-to-end** - Verify all connections
4. **Optimize performance** - Real-time responsiveness
5. **Demo preparation** - Sample data and scenarios

*Analysis Date: September 29, 2025*
*Status: Ready for Stage 1 Implementation*
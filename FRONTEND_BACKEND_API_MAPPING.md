# JanuSec Platform - Frontend to Backend API Mapping

## Executive Summary
**Status**: Complete analysis of janusec-platform-complete.html frontend and existing backend APIs
**Backend Server**: Running on http://localhost:8000
**Integration Strategy**: Real-time API connections with live data feeds

---

## 1. HEADER STATUS & METRICS

### Frontend Components
- **Connection Status**: "Connected to XDR" indicator with pulse animation
- **Last Update**: Dynamic timestamp ("2 min ago")
- **Alert Counters**: Critical (2), High (8), Medium (15) with color coding

### Backend APIs
✅ **EXISTING**: `/api/v1/metrics/executive` - Basic metrics aggregation
✅ **EXISTING**: `/api/v1/metrics/summary` - Summary with alert counts
🔧 **ENHANCE NEEDED**: Add XDR connection status and last update timestamp

#### Required Implementation
```javascript
// Frontend polling function
async function updateHeaderStatus() {
    const response = await fetch('/api/v1/status/dashboard');
    const data = await response.json();

    document.getElementById('criticalCount').textContent = data.alerts.critical;
    document.getElementById('highCount').textContent = data.alerts.high;
    document.getElementById('mediumCount').textContent = data.alerts.medium;
    document.getElementById('lastUpdate').textContent = data.last_update;
}
setInterval(updateHeaderStatus, 30000); // Every 30 seconds
```

---

## 2. DASHBOARD METRICS CARDS

### Frontend Components
- **Critical Threats**: Real-time count (currently shows "2")
- **Artifacts Analyzed**: Total processed files (currently shows "342")
- **Detection Rate**: Success percentage (currently shows "98.2%")
- **Avg Response Time**: Processing speed (currently shows "1.2s")

### Backend APIs
✅ **EXISTING**: `/api/v1/metrics/executive` - Has decision counts and realized costs
✅ **EXISTING**: `/api/v1/metrics/summary` - Has decision counts and heavy ops
🆕 **NEW REQUIRED**: `/api/v1/dashboard/metrics` - Dedicated dashboard metrics

#### New Endpoint Needed
```python
@router.get('/api/v1/dashboard/metrics')
async def dashboard_metrics(tenant_id: str = None):
    return {
        'critical_threats': count_critical_threats(),
        'artifacts_analyzed': count_analyzed_artifacts(),
        'detection_rate': calculate_detection_rate(),
        'avg_response_time': get_avg_response_time(),
        'timestamp': time.time()
    }
```

---

## 3. FILE UPLOAD SYSTEM

### Frontend Components
- **Upload Zone**: Drag & drop with visual feedback
- **Multi-format Support**: PCAP, EVTX, JSON, CSV, LOG files
- **Progress Tracking**: Real-time processing status
- **Results Display**: Analysis results with threat detection

### Backend APIs
✅ **FULLY IMPLEMENTED**: `/api/v1/upload/files` - Complete multi-format processor
✅ **EXISTING**: `/api/v1/upload/supported-formats` - Format specifications
✅ **EXISTING**: `/api/v1/upload/stats` - Upload statistics

#### Integration Ready
The upload system is **100% FUNCTIONAL** with existing backend. Frontend needs:
```javascript
async function handleFiles(files) {
    const formData = new FormData();
    for (const file of files) {
        formData.append('files', file);
    }

    const response = await fetch('/api/v1/upload/files', {
        method: 'POST',
        headers: { 'X-Tenant-ID': currentTenant },
        body: formData
    });

    const result = await response.json();
    updateDashboardMetrics(result);
    showNotification(`Processed ${result.files_processed} files - ${result.total_threats_detected} threats detected`);
}
```

---

## 4. ALERT FEED SYSTEM

### Frontend Components
- **Live Alert Stream**: Real-time scrolling alerts
- **Alert Details**: Title, MITRE techniques, timing, severity
- **Auto-refresh**: New alerts every 30 seconds
- **Severity Indicators**: Color-coded severity bars

### Backend APIs
✅ **FULLY IMPLEMENTED**: `/api/v1/alerts/recent` - Recent alerts with limit
✅ **EXISTING**: `/api/v1/alerts/search` - Advanced alert filtering
✅ **EXISTING**: Alert ring buffer with real-time updates

#### Integration Ready
```javascript
async function refreshAlertFeed() {
    const response = await fetch('/api/v1/alerts/recent?limit=10');
    const data = await response.json();

    const alertFeed = document.getElementById('alertFeed');
    alertFeed.innerHTML = '';

    data.alerts.forEach(alert => {
        const alertElement = createAlertElement(alert);
        alertFeed.appendChild(alertElement);
    });
}
setInterval(refreshAlertFeed, 30000);
```

---

## 5. INVESTIGATION CONSOLE

### Frontend Components
- **Active Investigation**: Currently investigating "powerscan.exe"
- **Evidence List**: SHA256, timestamps, affected hosts
- **Cost Analysis**: Detection costs ($342) vs Prevented damage ($8,420)
- **MITRE Mapping**: T1059, T1105, T1057 technique badges

### Backend APIs
✅ **EXISTING**: `/api/v1/finops/overview` - Cost analysis with EWMA
🆕 **NEW REQUIRED**: `/api/v1/investigation/active` - Current investigation details
🆕 **NEW REQUIRED**: `/api/v1/mitre/mapping` - MITRE ATT&CK technique mapping

#### New Endpoints Needed
```python
@router.get('/api/v1/investigation/active')
async def get_active_investigation(tenant_id: str = None):
    return {
        'investigation_id': 'powerscan-001',
        'target': 'powerscan.exe',
        'sha256': 'a7c24b7dc90e8a67f9c3b1d4e5f6789abcdef',
        'first_seen': '2025-09-23T14:32:00Z',
        'affected_hosts': ['DESKTOP-A1B2C3', 'LAPTOP-X4Y5Z6'],
        'mitre_techniques': ['T1059', 'T1105', 'T1057'],
        'status': 'active'
    }

@router.get('/api/v1/mitre/techniques/{investigation_id}')
async def get_mitre_mapping(investigation_id: str):
    return {
        'techniques': [
            {'id': 'T1059', 'name': 'Command Execution', 'confidence': 0.95},
            {'id': 'T1105', 'name': 'Remote File Copy', 'confidence': 0.87},
            {'id': 'T1057', 'name': 'Process Discovery', 'confidence': 0.73}
        ]
    }
```

---

## 6. INTEGRATION MANAGEMENT

### Frontend Components
- **Integration Buttons**: XDR (connected), ZEEK, Slack, Teams
- **Status Indicators**: Visual connection status
- **Webhook Testing**: Integration toggle functionality

### Backend APIs
🆕 **NEW REQUIRED**: `/api/v1/integrations/status` - Integration health checks
🆕 **NEW REQUIRED**: `/api/v1/integrations/toggle` - Enable/disable integrations
🆕 **NEW REQUIRED**: `/api/v1/webhooks/test` - Test webhook connections

#### New Endpoints Needed
```python
@router.get('/api/v1/integrations/status')
async def integration_status():
    return {
        'xdr': {'connected': True, 'last_sync': time.time()},
        'zeek': {'connected': False, 'error': 'Connection timeout'},
        'slack': {'connected': False, 'webhook_url': None},
        'teams': {'connected': False, 'webhook_url': None}
    }

@router.post('/api/v1/integrations/{service}/toggle')
async def toggle_integration(service: str, enabled: bool):
    # Update integration status
    return {'service': service, 'enabled': enabled}
```

---

## 7. NAVIGATION VIEWS

### Frontend Components
- **Dashboard**: Current view (✅ Ready)
- **Artifacts**: File analysis view (needs `/api/v1/artifacts/list`)
- **Active Threats**: Threat overview (needs `/api/v1/threats/active`)
- **Threat Hunt**: Hunt interface (✅ has `/api/v1/hunt/lanes/events`)
- **MITRE ATT&CK**: Framework view (needs `/api/v1/mitre/matrix`)
- **YARA Rules**: Rule management (needs `/api/v1/yara/rules`)
- **Timeline**: Event timeline (needs `/api/v1/events/timeline`)
- **Settings**: Platform config (needs `/api/v1/settings`)

### Backend APIs Status
✅ **Hunt Lanes**: `/api/v1/hunt/lanes/events` - WORKING
✅ **Upload Stats**: `/api/v1/upload/stats` - For artifacts view
🆕 **NEW REQUIRED**: Multiple endpoints for complete navigation

---

## 8. ACTION BUTTONS

### Frontend Components
- **Create Security Incident**: Button in investigation panel
- **Export Investigation Report**: Generate PDF/JSON reports
- **Send to SIEM**: Forward data to SIEM systems

### Backend APIs
🆕 **NEW REQUIRED**: `/api/v1/incidents/create` - Create security incident
🆕 **NEW REQUIRED**: `/api/v1/reports/export` - Generate investigation report
🆕 **NEW REQUIRED**: `/api/v1/siem/forward` - SIEM integration

---

## IMPLEMENTATION PRIORITY

### Phase 1: Core Dashboard (Ready to Deploy)
✅ **Header Status**: Use existing metrics endpoints
✅ **File Upload**: Fully functional with existing backend
✅ **Alert Feed**: Fully functional with existing endpoints
✅ **Cost Analysis**: Working with finops endpoint

### Phase 2: Investigation Console (Needs 3 New Endpoints)
🔧 **Active Investigation**: New `/api/v1/investigation/active`
🔧 **MITRE Mapping**: New `/api/v1/mitre/mapping`
🔧 **Integration Status**: New `/api/v1/integrations/status`

### Phase 3: Navigation Views (Needs 6 New Endpoints)
🔧 **Artifacts View**: New `/api/v1/artifacts/list`
🔧 **Active Threats**: New `/api/v1/threats/active`
🔧 **MITRE Matrix**: New `/api/v1/mitre/matrix`
🔧 **YARA Rules**: New `/api/v1/yara/rules`
🔧 **Timeline**: New `/api/v1/events/timeline`
🔧 **Settings**: New `/api/v1/settings`

### Phase 4: Actions (Needs 3 New Endpoints)
🔧 **Incident Creation**: New `/api/v1/incidents/create`
🔧 **Report Export**: New `/api/v1/reports/export`
🔧 **SIEM Forward**: New `/api/v1/siem/forward`

---

## IMMEDIATE ACTION PLAN

### 1. Copy Frontend to Static Directory
```bash
cp dump/Design/janusec-platform-complete.html frontend/static/janusec-platform-complete.html
```

### 2. Update Frontend API Calls
Replace all mock data with real API calls to existing endpoints.

### 3. Create Missing Endpoints
Implement the 15 new endpoints identified above.

### 4. Test Integration
Verify all frontend features work with backend APIs.

---

## CONCLUSION

**Total Backend Endpoints Needed**: 15 new endpoints
**Existing Functional**: 8 endpoints (File upload, alerts, metrics, hunt lanes, finops)
**Implementation Time**: ~2-3 hours for core functionality
**Demo Ready Status**: Phase 1 can be deployed immediately

The platform has a **solid foundation** with existing APIs for core security operations. The new endpoints are primarily for UI navigation and advanced features.
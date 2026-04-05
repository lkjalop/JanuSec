# 🚀 JanuSec Platform - Quick Reference Guide

## 📍 **FRONTEND LOCATIONS** (Copy this for any AI assistant)

### **Primary Files to Reference:**
```
LIVE PLATFORM: D:\AI\Threat_thy_sniffer\frontend\static\janusec-platform-complete-LIVE.html
ORIGINAL DESIGN: D:\AI\Threat_thy_sniffer\dump\Design\janusec-platform-complete.html
API MAPPING: D:\AI\Threat_thy_sniffer\FRONTEND_BACKEND_API_MAPPING.md
DASHBOARD APIs: D:\AI\Threat_thy_sniffer\src\api\dashboard_endpoints.py
```

### **Start Server Command:**
```bash
cd "D:\AI\Threat_thy_sniffer" && python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload
```

### **Access URLs:**
- **🔴 LIVE PLATFORM**: http://localhost:8000/static/janusec-platform-complete-LIVE.html
- **📚 API DOCS**: http://localhost:8000/docs
- **⚡ HEALTH CHECK**: http://localhost:8000/health

---

## 🎯 **HOW TO TELL ANY AI WHERE THE FRONTEND IS:**

**Simple Prompt:**
> "The main frontend is at `D:\AI\Threat_thy_sniffer\frontend\static\janusec-platform-complete-LIVE.html` - this is the EXACT original design with real backend API connections. The backend APIs are in `src/api/dashboard_endpoints.py`. Start the server with `cd D:\AI\Threat_thy_sniffer && python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload`"

---

## 🌐 **CURRENT STATUS**
- ✅ **Server**: RUNNING on http://localhost:8000
- ✅ **Frontend**: LIVE and fully integrated
- ✅ **APIs**: All dashboard endpoints working
- ✅ **File Upload**: Multi-format support active
- ✅ **Real-time Data**: 30-second auto-refresh

---

## 🔄 **QUICK RESTART COMMANDS:**
```bash
# Kill any existing servers
taskkill /f /im python.exe

# Start fresh
cd "D:\AI\Threat_thy_sniffer"
python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload
```

---

## 📋 **ARCHITECTURE SUMMARY:**
- **Backend**: FastAPI with async processing
- **Frontend**: Pure HTML/CSS/JS with real API integration
- **Database**: PostgreSQL/Neon (optional, has fallbacks)
- **File Processing**: PCAP, EVTX, JSON, CSV, LOG support
- **Security**: Multi-tenant, rate-limited, CORS-protected
- **Monitoring**: Prometheus metrics, health checks
- **Real-time**: WebSocket-ready architecture
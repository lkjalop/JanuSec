# 🤖 JanuSec Platform - AI Assistant Quick Setup

## 📋 **Copy This Prompt for Any AI Assistant:**

```
The JanuSec threat detection platform is located at D:\AI\Threat_thy_sniffer

FRONTEND LOCATION:
- Main live platform: frontend/static/janusec-platform-live-complete.html
- Original design: dump/Design/janusec-platform-complete.html

BACKEND APIS:
- Dashboard endpoints: src/api/dashboard_endpoints.py
- Main app: src/api/app.py

START SERVER:
cd "D:\AI\Threat_thy_sniffer" && python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000 --reload

ACCESS URLS:
- Live Platform: http://localhost:8000/static/janusec-platform-live-complete.html
- API Docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

The platform is fully integrated with working file upload, real-time alerts, dashboard metrics, and investigation console. All backend APIs are functional.
```

## 🎯 **For Azure Deployment:**

```
To deploy to Azure, use the files in azure-deployment/:
- Terraform: azure-deployment/terraform/main.tf
- Docker: azure-deployment/Dockerfile
- Deploy script: azure-deployment/deploy.sh

Run: ./azure-deployment/deploy.sh for one-click deployment
```

## 🔍 **Key Files to Reference:**

```
PLATFORM_REFERENCE_GUIDE.md - Complete reference
FRONTEND_BACKEND_API_MAPPING.md - API documentation
azure-deployment/README.md - Azure deployment guide
```

## ⚡ **Quick Health Check:**

```bash
# Test if everything is working:
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/dashboard/status
```
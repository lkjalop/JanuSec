# 🚀 JanuSec Platform - Azure Deployment Guide

## 🎯 **Quick Azure Deployment**

### **Option 1: One-Click Deployment**
```bash
# Make script executable and run
chmod +x azure-deployment/deploy.sh
./azure-deployment/deploy.sh
```

### **Option 2: Manual Terraform Deployment**
```bash
# 1. Install prerequisites
# - Azure CLI: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
# - Terraform: https://www.terraform.io/downloads.html
# - Docker: https://docs.docker.com/get-docker/

# 2. Login to Azure
az login

# 3. Deploy with Terraform
cd azure-deployment/terraform
terraform init
terraform plan
terraform apply
```

---

## 🏗️ **What Gets Deployed**

### **Azure Resources Created:**
- ✅ **Container App** - Hosts the JanuSec platform
- ✅ **PostgreSQL Flexible Server** - Database for persistence
- ✅ **Container Registry** - For Docker images
- ✅ **Log Analytics Workspace** - For monitoring
- ✅ **Storage Account** - For artifacts and logs
- ✅ **Key Vault** - For secrets management
- ✅ **Container App Environment** - Runtime environment

### **Estimated Monthly Cost:**
- **Development**: ~$50-100/month
- **Production**: ~$200-500/month
- **Demo/Trial**: ~$20-50/month

---

## 🌐 **Access Your Deployed Platform**

After deployment, you'll get:
```
🔗 Platform URL: https://janusec-platform-app-dev.kindflower-12345678.eastus.azurecontainerapps.io
📱 Frontend: [URL]/static/janusec-platform-live-complete.html
📚 API Docs: [URL]/docs
💓 Health: [URL]/health
```

---

## 🔧 **Configuration Options**

### **Environment Variables:**
```bash
# In terraform/main.tf, customize these:
DB_TYPE=postgres
ENVIRONMENT=production
RATE_LIMIT_ENABLED=1
ALLOWED_ORIGINS=*
```

### **Scaling Configuration:**
```hcl
# In main.tf Container App section:
min_replicas = 1    # Minimum instances
max_replicas = 10   # Maximum instances
cpu          = 2    # CPU cores
memory       = "4Gi" # Memory
```

---

## 🛡️ **Security Features**

### **Built-in Security:**
- ✅ **HTTPS Only** - Automatic SSL/TLS
- ✅ **Rate Limiting** - API protection
- ✅ **CORS Protection** - Cross-origin security
- ✅ **Key Vault Integration** - Secrets management
- ✅ **Network Security** - Container isolation
- ✅ **Authentication** - Multi-tenant support

### **Optional Enhancements:**
- 🔧 Azure Active Directory integration
- 🔧 API Management Gateway
- 🔧 Web Application Firewall
- 🔧 Private networking (VNet integration)

---

## 📊 **Monitoring & Logging**

### **Included Monitoring:**
- ✅ **Application Insights** - Performance monitoring
- ✅ **Log Analytics** - Centralized logging
- ✅ **Health Checks** - Automatic monitoring
- ✅ **Container Metrics** - Resource usage

### **Custom Dashboards:**
Access built-in dashboards for:
- Threat detection metrics
- API performance
- Security alerts
- Cost analysis

---

## 🔄 **CI/CD Integration**

### **GitHub Actions Example:**
```yaml
# .github/workflows/deploy.yml
name: Deploy to Azure
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy to Azure
        run: ./azure-deployment/deploy.sh
```

---

## 🚨 **Troubleshooting**

### **Common Issues:**

**1. Deployment Fails:**
```bash
# Check Azure CLI login
az account show

# Verify subscription permissions
az role assignment list --assignee $(az account show --query user.name -o tsv)
```

**2. Application Won't Start:**
```bash
# Check container logs
az containerapp logs show --name janusec-platform-app-dev --resource-group janusec-platform-rg
```

**3. Database Connection Issues:**
```bash
# Verify PostgreSQL firewall rules
az postgres flexible-server firewall-rule list --resource-group janusec-platform-rg --name janusec-platform-db-dev
```

---

## 💰 **Cost Optimization**

### **Development Environment:**
```hcl
# Use smaller SKUs for dev/test
sku_name = "B_Standard_B1ms"  # Database
account_replication_type = "LRS"  # Storage
min_replicas = 0  # Auto-scale to zero
```

### **Production Environment:**
```hcl
# Use appropriate SKUs for production
sku_name = "GP_Standard_D2s_v3"  # Database
account_replication_type = "GRS"  # Storage
min_replicas = 2  # High availability
```

---

## 🎯 **For Demos & Trials**

### **Quick Demo Setup:**
```bash
# Deploy minimal demo environment
terraform apply -var="environment=demo" -var="sku_tier=Basic"
```

### **Share with Others:**
1. **Public URL**: Share the Container App URL
2. **Demo Credentials**: No authentication required for demo
3. **Sample Data**: Platform includes demo threats and alerts
4. **File Upload**: Works with sample PCAP/JSON files

---

## 📞 **Support & Next Steps**

### **Getting Help:**
- 📚 Check logs in Azure Portal
- 🔍 Use Application Insights for troubleshooting
- 💬 Review container app logs
- 🛠️ Modify Terraform variables for customization

### **Production Readiness:**
- [ ] Set up custom domain
- [ ] Configure Azure AD authentication
- [ ] Set up backup policies
- [ ] Configure monitoring alerts
- [ ] Set up CI/CD pipeline
- [ ] Review security settings

**🎉 Your JanuSec Platform is now ready for Azure!**
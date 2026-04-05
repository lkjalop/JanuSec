#!/bin/bash
# JanuSec Platform - Azure Deployment Script

set -e

echo "🚀 JanuSec Platform - Azure Deployment"
echo "======================================"

# Configuration
RESOURCE_GROUP="janusec-platform-rg"
LOCATION="eastus"
APP_NAME="janusec-platform"
ENVIRONMENT="demo"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
print_status "Checking prerequisites..."

if ! command -v az &> /dev/null; then
    print_error "Azure CLI is not installed. Please install it first."
    exit 1
fi

if ! command -v terraform &> /dev/null; then
    print_error "Terraform is not installed. Please install it first."
    exit 1
fi

if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install it first."
    exit 1
fi

print_success "All prerequisites met!"

# Login to Azure
print_status "Checking Azure login status..."
if ! az account show &> /dev/null; then
    print_status "Please log in to Azure..."
    az login
fi

# Get subscription info
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
print_success "Using Azure subscription: $SUBSCRIPTION_ID"

# Build Docker image
print_status "Building Docker image..."
IMAGE_TAG=${IMAGE_TAG:-latest}
docker build -t ${APP_NAME}:${IMAGE_TAG} -f azure-deployment/Dockerfile .

# Push to Azure Container Registry
ACR_NAME="${APP_NAME}acr${ENVIRONMENT}"
ACR_SERVER="${ACR_NAME}.azurecr.io"
print_status "Logging in to Azure Container Registry: ${ACR_SERVER}"
az acr login --name ${ACR_NAME}
docker tag ${APP_NAME}:${IMAGE_TAG} ${ACR_SERVER}/${APP_NAME}:${IMAGE_TAG}
print_status "Pushing image to ACR..."
docker push ${ACR_SERVER}/${APP_NAME}:${IMAGE_TAG}

# Deploy with Terraform
print_status "Initializing Terraform..."
cd azure-deployment/terraform
terraform init

print_status "Planning Terraform deployment..."
terraform plan \
    -var="resource_group_name=${RESOURCE_GROUP}" \
    -var="location=${LOCATION}" \
    -var="app_name=${APP_NAME}" \
    -var="environment=${ENVIRONMENT}" \
    -var="container_image=${ACR_SERVER}/${APP_NAME}:${IMAGE_TAG}" \
    -var="allowed_origins=${ALLOWED_ORIGINS:-https://janusec.example.com}"

print_warning "This will create Azure resources that may incur costs."
read -p "Do you want to proceed with deployment? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_status "Deployment cancelled."
    exit 0
fi

print_status "Applying Terraform configuration..."
terraform apply \
    -var="resource_group_name=${RESOURCE_GROUP}" \
    -var="location=${LOCATION}" \
    -var="app_name=${APP_NAME}" \
    -var="environment=${ENVIRONMENT}" \
    -var="container_image=${ACR_SERVER}/${APP_NAME}:${IMAGE_TAG}" \
    -var="allowed_origins=${ALLOWED_ORIGINS:-https://janusec.example.com}" \
    -auto-approve

# Get outputs
APP_URL=$(terraform output -raw application_url)
DB_FQDN=$(terraform output -raw database_fqdn)
ACR_SERVER=$(terraform output -raw container_registry_login_server)

print_success "Deployment completed successfully!"
echo ""
echo "🎉 JanuSec Platform Deployed!"
echo "============================="
echo "📱 Application URL: $APP_URL"
echo "🗄️  Database FQDN: $DB_FQDN"
echo "📦 Container Registry: $ACR_SERVER"
echo ""
echo "🔗 Access your platform at: $APP_URL/static/janusec-platform-live-complete.html"
echo ""
echo "📚 Next steps:"
echo "1. Configure DNS (optional)"
echo "2. Set up custom domain and SSL"
echo "3. Configure monitoring and alerts"
echo "4. Set up CI/CD pipeline"

cd ../..

#!/bin/bash

# ChromaDB Admin Deployment Script
# Usage: ./scripts/deploy.sh [environment] [action]
# Example: ./scripts/deploy.sh local install
#          ./scripts/deploy.sh staging upgrade

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CHART_PATH="$PROJECT_ROOT/helm/chromadb-admin"

# Default values
ENVIRONMENT=${1:-local}
ACTION=${2:-install}
NAMESPACE="chromadb-admin"
RELEASE_NAME="chromadb-admin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if helm is installed
    if ! command -v helm &> /dev/null; then
        log_error "helm is not installed or not in PATH"
        exit 1
    fi
    
    # Check if we can connect to Kubernetes cluster
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Setup Helm repositories
setup_helm_repos() {
    log_info "Setting up Helm repositories..."
    
    # Add Bitnami repository for PostgreSQL
    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm repo update
    
    log_success "Helm repositories configured"
}

# Build and load Docker image for local development
build_local_image() {
    if [[ "$ENVIRONMENT" == "local" ]]; then
        log_info "Building local Docker image..."
        
        cd "$PROJECT_ROOT"
        
        # Build the image
        docker build -t chromadb-admin:local .
        
        # Load image into kind/minikube if available
        if command -v kind &> /dev/null; then
            kind load docker-image chromadb-admin:local --name kind || true
        elif command -v minikube &> /dev/null; then
            minikube image load chromadb-admin:local || true
        fi
        
        log_success "Local Docker image built and loaded"
    fi
}

# Create namespace
create_namespace() {
    log_info "Creating namespace: $NAMESPACE"
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
}

# Get values file based on environment
get_values_file() {
    case $ENVIRONMENT in
        local)
            echo "$PROJECT_ROOT/helm/chromadb-admin/values-local.yaml"
            ;;
        development)
            echo "$PROJECT_ROOT/helm/chromadb-admin/values-dev.yaml"
            ;;
        staging)
            echo "$PROJECT_ROOT/helm/chromadb-admin/values-staging.yaml"
            ;;
        production)
            echo "$PROJECT_ROOT/helm/chromadb-admin/values-prod.yaml"
            ;;
        *)
            echo "$PROJECT_ROOT/helm/chromadb-admin/values.yaml"
            ;;
    esac
}

# Install or upgrade the chart
deploy_chart() {
    local values_file
    values_file=$(get_values_file)
    
    log_info "Deploying ChromaDB Admin to $ENVIRONMENT environment..."
    
    # Update dependencies
    cd "$CHART_PATH"
    helm dependency update
    
    # Common Helm arguments
    local helm_args=(
        "$RELEASE_NAME"
        "$CHART_PATH"
        "--namespace" "$NAMESPACE"
        "--create-namespace"
        "--timeout" "10m"
    )
    
    # Add values file if it exists
    if [[ -f "$values_file" ]]; then
        helm_args+=("--values" "$values_file")
        log_info "Using values file: $values_file"
    else
        log_warning "Values file not found: $values_file, using default values"
    fi
    
    # Add environment-specific overrides
    case $ENVIRONMENT in
        local)
            helm_args+=(
                "--set" "chromadbAdmin.image.repository=chromadb-admin"
                "--set" "chromadbAdmin.image.tag=local"
                "--set" "chromadbAdmin.image.pullPolicy=Never"
                "--set" "chromadbAdmin.replicaCount=1"
                "--set" "postgresql.primary.persistence.size=1Gi"
                "--set" "chromadb.persistence.size=1Gi"
            )
            ;;
        development)
            helm_args+=(
                "--set" "chromadbAdmin.replicaCount=1"
                "--set" "postgresql.primary.persistence.size=5Gi"
                "--set" "chromadb.persistence.size=5Gi"
            )
            ;;
    esac
    
    # Perform the action
    case $ACTION in
        install)
            helm install "${helm_args[@]}"
            ;;
        upgrade)
            helm upgrade "${helm_args[@]}"
            ;;
        template)
            helm template "${helm_args[@]}" --debug
            ;;
        *)
            log_error "Unknown action: $ACTION"
            exit 1
            ;;
    esac
}

# Wait for deployment to be ready
wait_for_deployment() {
    if [[ "$ACTION" != "template" ]]; then
        log_info "Waiting for deployment to be ready..."
        
        # Wait for deployments
        kubectl wait --for=condition=available --timeout=600s \
            deployment -l app.kubernetes.io/instance="$RELEASE_NAME" \
            -n "$NAMESPACE"
        
        log_success "Deployment is ready!"
    fi
}

# Show deployment status
show_status() {
    if [[ "$ACTION" != "template" ]]; then
        log_info "Deployment status:"
        
        echo ""
        echo "Pods:"
        kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/instance="$RELEASE_NAME"
        
        echo ""
        echo "Services:"
        kubectl get services -n "$NAMESPACE" -l app.kubernetes.io/instance="$RELEASE_NAME"
        
        echo ""
        echo "Ingresses:"
        kubectl get ingress -n "$NAMESPACE" -l app.kubernetes.io/instance="$RELEASE_NAME" 2>/dev/null || echo "No ingresses found"
        
        # Show access information
        echo ""
        log_info "Access Information:"
        
        # Port-forward command for local access
        local web_service
        web_service=$(kubectl get service -n "$NAMESPACE" -l app.kubernetes.io/instance="$RELEASE_NAME",app.kubernetes.io/component=web -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        
        if [[ -n "$web_service" ]]; then
            echo "  Local access (port-forward):"
            echo "    kubectl port-forward service/$web_service -n $NAMESPACE 8080:80"
            echo "    Then open: http://localhost:8080"
        fi
        
        # Show initial admin credentials
        echo ""
        log_info "Initial Admin Credentials:"
        local secret_name="${RELEASE_NAME}-secret"
        if kubectl get secret "$secret_name" -n "$NAMESPACE" &>/dev/null; then
            local admin_password
            admin_password=$(kubectl get secret "$secret_name" -n "$NAMESPACE" -o jsonpath='{.data.INITIAL_ADMIN_PASSWORD}' | base64 -d 2>/dev/null || echo "Not available")
            echo "    Username: admin"
            echo "    Password: $admin_password"
        fi
    fi
}

# Cleanup function
cleanup() {
    case $1 in
        uninstall)
            log_info "Uninstalling ChromaDB Admin..."
            helm uninstall "$RELEASE_NAME" -n "$NAMESPACE" || true
            ;;
        purge)
            log_info "Purging ChromaDB Admin (including PVCs)..."
            helm uninstall "$RELEASE_NAME" -n "$NAMESPACE" || true
            kubectl delete pvc -l app.kubernetes.io/instance="$RELEASE_NAME" -n "$NAMESPACE" || true
            kubectl delete namespace "$NAMESPACE" || true
            ;;
        *)
            log_error "Unknown cleanup action: $1"
            exit 1
            ;;
    esac
}

# Show help
show_help() {
    cat << EOF
ChromaDB Admin Deployment Script

Usage: $0 [environment] [action]

Environments:
  local       - Local development (default)
  development - Development environment
  staging     - Staging environment
  production  - Production environment

Actions:
  install     - Install the chart (default)
  upgrade     - Upgrade existing installation
  template    - Generate and display templates
  uninstall   - Remove the installation
  purge       - Remove installation and all data

Examples:
  $0                          # Install to local environment
  $0 local install            # Install to local environment
  $0 staging upgrade          # Upgrade staging environment
  $0 production template      # Show production templates
  $0 local uninstall          # Uninstall from local
  $0 local purge             # Completely remove local installation

Environment Variables:
  NAMESPACE     - Kubernetes namespace (default: chromadb-admin)
  RELEASE_NAME  - Helm release name (default: chromadb-admin)

EOF
}

# Main execution
main() {
    case $ACTION in
        help|--help|-h)
            show_help
            exit 0
            ;;
        uninstall|purge)
            cleanup "$ACTION"
            exit 0
            ;;
    esac
    
    check_prerequisites
    setup_helm_repos
    build_local_image
    create_namespace
    deploy_chart
    wait_for_deployment
    show_status
    
    log_success "Deployment completed successfully!"
}

# Run main function
main "$@" 
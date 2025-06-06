# ChromaDB Admin Helm Charts

This directory contains Helm charts for deploying ChromaDB Admin and related components.

## Available Charts

### chromadb-admin

The main chart for deploying ChromaDB Admin Panel - a web-based administration interface for ChromaDB.

**Features:**
- ChromaDB Admin web interface
- Optional PostgreSQL database
- Configurable ChromaDB instance
- Ingress support
- Persistent storage options
- Security configurations

## Usage

### Adding the Helm Repository

```bash
helm repo add chromadb-admin https://maxintech.github.io/chromadb-admin
helm repo update
```

### Installing Charts

```bash
# Install with default values
helm install my-chromadb-admin chromadb-admin/chromadb-admin

# Install with custom values
helm install my-chromadb-admin chromadb-admin/chromadb-admin -f my-values.yaml

# Install in a specific namespace
helm install my-chromadb-admin chromadb-admin/chromadb-admin --namespace chromadb --create-namespace
```

### Upgrading Charts

```bash
helm upgrade my-chromadb-admin chromadb-admin/chromadb-admin
```

### Uninstalling Charts

```bash
helm uninstall my-chromadb-admin
```

## Chart Development

### Prerequisites

- Helm 3.14+
- Kubernetes 1.19+

### Local Testing

```bash
# Lint the chart
helm lint charts/chromadb-admin/

# Template the chart to see generated manifests
helm template test charts/chromadb-admin/ --debug

# Test with custom values
helm template test charts/chromadb-admin/ -f charts/chromadb-admin/values-local.yaml
```

### Chart Structure

```
charts/
└── chromadb-admin/
    ├── Chart.yaml          # Chart metadata
    ├── values.yaml         # Default configuration values
    ├── values-prod.yaml    # Production configuration
    ├── values-local.yaml   # Local development configuration
    ├── README.md          # Chart documentation
    └── templates/         # Kubernetes manifest templates
```

## Contributing

When making changes to charts:

1. Update the chart version in `Chart.yaml`
2. Test locally using the commands above
3. Update documentation if needed
4. Create a pull request

Charts are automatically published when tags are created following semantic versioning (e.g., `v1.0.0`). 
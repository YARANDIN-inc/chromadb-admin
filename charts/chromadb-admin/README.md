# ChromaDB Admin Helm Chart

A Helm chart for deploying ChromaDB Admin Panel - A web-based administration interface for ChromaDB vector databases.

## Features

- 🐳 **Complete Stack**: Deploys ChromaDB Admin, ChromaDB server, and PostgreSQL database
- 🔒 **Security Focused**: Built-in CSRF protection, secure sessions, and input validation
- 📊 **Production Ready**: Auto-scaling, health checks, and resource management
- 🔧 **Configurable**: Extensive configuration options for all components
- 📈 **Monitoring**: Built-in support for Prometheus monitoring
- 🌐 **Ingress Support**: Easy external access configuration

## Prerequisites

- Kubernetes 1.19+
- Helm 3.8+
- PV provisioner support in the underlying infrastructure (for persistence)

## Installation

### Add the Helm Repository

```bash
# Add the repository
helm repo add chromadb-admin https://yourusername.github.io/chromadb-admin

# Update repository
helm repo update
```

### Quick Start

```bash
# Install with default values
helm install my-chromadb-admin chromadb-admin/chromadb-admin

# Install with custom values
helm install my-chromadb-admin chromadb-admin/chromadb-admin -f values.yaml

# Install in a specific namespace
helm install my-chromadb-admin chromadb-admin/chromadb-admin --namespace chromadb --create-namespace
```

### Using OCI Registry (GitHub Container Registry)

```bash
# Install from GHCR
helm install my-chromadb-admin oci://ghcr.io/yourusername/charts/chromadb-admin --version 0.1.0
```

## Configuration

### Basic Configuration

```yaml
# Basic configuration example
chromadbAdmin:
  replicaCount: 3
  config:
    initialAdmin:
      enabled: true
      username: "admin"
      email: "admin@yourcompany.com"
      password: "secure-password-123"

ingress:
  enabled: true
  hosts:
    - host: chromadb-admin.yourcompany.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: chromadb-admin-tls
      hosts:
        - chromadb-admin.yourcompany.com
```

### External Database

```yaml
# Use external PostgreSQL
postgresql:
  enabled: false

chromadbAdmin:
  config:
    databaseUrl: "postgresql://user:password@external-postgres:5432/chromadb_admin"
```

### External ChromaDB

```yaml
# Use external ChromaDB
chromadb:
  enabled: false

chromadbAdmin:
  config:
    chromadbUrl: "http://external-chromadb:8000"
    chromadbToken: "your-auth-token"
```

### Production Configuration

```yaml
# Production-ready configuration
chromadbAdmin:
  replicaCount: 5
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 500m
      memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

postgresql:
  primary:
    persistence:
      size: 50Gi
    resources:
      limits:
        cpu: 1000m
        memory: 1Gi

chromadb:
  resources:
    limits:
      cpu: 2000m
      memory: 4Gi
  persistence:
    size: 100Gi
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `chromadbAdmin.replicaCount` | int | `3` | Number of ChromaDB Admin replicas |
| `chromadbAdmin.image.repository` | string | `"ghcr.io/yourusername/chromadb-admin"` | Image repository |
| `chromadbAdmin.image.tag` | string | `""` | Image tag (defaults to chart appVersion) |
| `chromadbAdmin.config.secretKey` | string | `""` | Secret key for sessions (auto-generated if empty) |
| `chromadbAdmin.config.initialAdmin.enabled` | bool | `true` | Create initial admin user |
| `chromadbAdmin.config.initialAdmin.username` | string | `"admin"` | Initial admin username |
| `chromadbAdmin.config.initialAdmin.email` | string | `"admin@example.com"` | Initial admin email |
| `chromadbAdmin.config.initialAdmin.password` | string | `""` | Initial admin password (auto-generated if empty) |
| `chromadb.enabled` | bool | `true` | Deploy ChromaDB service |
| `chromadb.persistence.enabled` | bool | `true` | Enable persistence for ChromaDB |
| `chromadb.persistence.size` | string | `"20Gi"` | Size of ChromaDB storage |
| `postgresql.enabled` | bool | `true` | Deploy PostgreSQL database |
| `postgresql.auth.database` | string | `"chromadb_admin"` | PostgreSQL database name |
| `postgresql.auth.username` | string | `"chromadb"` | PostgreSQL username |
| `ingress.enabled` | bool | `false` | Enable ingress |
| `autoscaling.enabled` | bool | `false` | Enable horizontal pod autoscaling |

For a complete list of values, see [values.yaml](values.yaml).

## Upgrading

```bash
# Upgrade to latest version
helm upgrade my-chromadb-admin chromadb-admin/chromadb-admin

# Upgrade with new values
helm upgrade my-chromadb-admin chromadb-admin/chromadb-admin -f new-values.yaml
```

## Uninstalling

```bash
# Uninstall the release
helm uninstall my-chromadb-admin

# Uninstall and delete PVCs (WARNING: This will delete all data)
helm uninstall my-chromadb-admin
kubectl delete pvc --selector=app.kubernetes.io/instance=my-chromadb-admin
```

## Troubleshooting

### Common Issues

1. **Pod Crashes with Database Connection Error**
   ```bash
   # Check if PostgreSQL is running
   kubectl get pods -l app.kubernetes.io/component=postgresql
   
   # Check database credentials
   kubectl get secret my-chromadb-admin-secret -o yaml
   ```

2. **ChromaDB Connection Issues**
   ```bash
   # Check ChromaDB service
   kubectl get svc -l app.kubernetes.io/component=chromadb
   
   # Test ChromaDB connectivity
   kubectl run test-chromadb --rm -i --tty --image=curlimages/curl -- \
     curl http://my-chromadb-admin-chromadb:8000/api/v1/heartbeat
   ```

3. **Ingress Not Working**
   ```bash
   # Check ingress controller
   kubectl get ingressclass
   
   # Check ingress configuration
   kubectl describe ingress my-chromadb-admin-ingress
   ```

### Logs

```bash
# View application logs
kubectl logs -l app.kubernetes.io/component=web

# View ChromaDB logs
kubectl logs -l app.kubernetes.io/component=chromadb

# View PostgreSQL logs
kubectl logs -l app.kubernetes.io/component=postgresql
```

## Security Considerations

1. **Change Default Passwords**: Always set custom passwords for production deployments
2. **Enable TLS**: Configure TLS termination at ingress or load balancer
3. **Network Policies**: Implement network policies to restrict pod-to-pod communication
4. **Resource Limits**: Set appropriate resource limits to prevent resource exhaustion
5. **Regular Updates**: Keep the chart and images updated to get security patches

## Development

### Local Testing

```bash
# Template the chart
helm template my-chromadb-admin ./helm/chromadb-admin

# Lint the chart
helm lint ./helm/chromadb-admin

# Test with debug
helm install my-chromadb-admin ./helm/chromadb-admin --debug --dry-run
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This chart is licensed under the MIT License. See the [LICENSE](../../LICENSE) file for details.

## Support

- 📚 [Documentation](https://github.com/yourusername/chromadb-admin)
- 🐛 [Issue Tracker](https://github.com/yourusername/chromadb-admin/issues)
- 💬 [Discussions](https://github.com/yourusername/chromadb-admin/discussions) 
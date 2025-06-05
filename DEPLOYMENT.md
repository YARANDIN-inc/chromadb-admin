# ChromaDB Admin - Deployment Guide

This guide covers deploying ChromaDB Admin using Helm charts and setting up CI/CD pipelines.

## 🏗️ Architecture Overview

The deployment consists of three main components:

1. **ChromaDB Admin Panel** - Web application (FastAPI + HTML templates)
2. **ChromaDB Vector Database** - The vector database service
3. **PostgreSQL Database** - For application data and user management

## 📦 Helm Chart

### Quick Start

```bash
# Add the Helm repository
helm repo add chromadb-admin https://yourusername.github.io/chromadb-admin
helm repo update

# Install with default values
helm install my-chromadb-admin chromadb-admin/chromadb-admin

# Or install from OCI registry
helm install my-chromadb-admin oci://ghcr.io/yourusername/charts/chromadb-admin
```

### Local Development

```bash
# Clone the repository
git clone https://github.com/yourusername/chromadb-admin.git
cd chromadb-admin

# Deploy locally using the script
./scripts/deploy.sh local install

# Access the application
kubectl port-forward service/chromadb-admin-web -n chromadb-admin 8080:80
# Open http://localhost:8080
```

### Production Deployment

```bash
# Create production values file
cat > values-production.yaml << EOF
chromadbAdmin:
  replicaCount: 5
  config:
    secretKey: "your-super-secret-key-64-chars-long"
    initialAdmin:
      username: "admin"
      email: "admin@yourcompany.com"
      password: "secure-admin-password"

ingress:
  enabled: true
  className: "nginx"
  hosts:
    - host: chromadb-admin.yourcompany.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: chromadb-admin-tls
      hosts:
        - chromadb-admin.yourcompany.com

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
EOF

# Deploy to production
helm install chromadb-admin chromadb-admin/chromadb-admin \
  --namespace chromadb-admin \
  --create-namespace \
  -f values-production.yaml
```

## 🔄 CI/CD Pipeline

### GitHub Actions Setup

The repository includes a comprehensive GitHub Actions workflow that:

1. **Builds and pushes Docker images** to GitHub Container Registry
2. **Lints and tests Helm charts**
3. **Runs security scans** with Trivy
4. **Publishes Helm charts** to multiple registries
5. **Creates GitHub releases** for tagged versions

### Registry Options (Free Tier)

#### 1. GitHub Container Registry (GHCR) + GitHub Pages (Recommended)

**Pros:**
- ✅ Completely free for public repositories
- ✅ Excellent GitHub integration
- ✅ Supports OCI artifacts
- ✅ Built-in security scanning

**Setup:**
```bash
# The CI/CD pipeline automatically publishes to:
# - Docker images: ghcr.io/username/chromadb-admin
# - Helm charts: ghcr.io/username/charts/chromadb-admin
# - Chart repository: https://username.github.io/repository-name
```

#### 2. Artifact Hub (Chart Discovery)

**Pros:**
- ✅ Free chart discovery platform
- ✅ Excellent visibility
- ✅ Automatic security scanning

**Setup:**
1. Publish your chart repository to GitHub Pages
2. Submit to [Artifact Hub](https://artifacthub.io/)

#### 3. Alternative Free Options

- **Harbor** (Self-hosted)
- **JFrog Artifactory** (Community edition)
- **Docker Hub** (Public repositories)

### CI/CD Features

#### Automated Versioning
- **Main branch**: `0.1.0-<commit-sha>`
- **Git tags**: `v1.0.0` → `1.0.0`
- **Pull requests**: `pr-123-<commit-sha>`

#### Multi-Architecture Support
- Builds for `linux/amd64` and `linux/arm64`
- Optimized for cloud and edge deployments

#### Security Scanning
- **Trivy** vulnerability scanning
- Results uploaded to GitHub Security tab
- Automated security advisories

#### Helm Chart Publishing
- **OCI Registry**: `ghcr.io/username/charts/chromadb-admin`
- **Traditional Repository**: `https://username.github.io/repository-name`
- **GitHub Releases**: Attached as artifacts

### Setting Up CI/CD

1. **Enable GitHub Container Registry**:
   ```bash
   # Go to Settings → Developer settings → Personal access tokens
   # Create token with 'write:packages' scope
   # No additional setup needed - GITHUB_TOKEN works automatically
   ```

2. **Enable GitHub Pages**:
   ```bash
   # Go to Repository Settings → Pages
   # Source: Deploy from a branch
   # Branch: gh-pages
   # Folder: / (root)
   ```

3. **Create Release**:
   ```bash
   # Tag and push a release
   git tag v1.0.0
   git push origin v1.0.0
   # CI/CD will automatically create release and publish charts
   ```

## 🏭 Production Considerations

### Security

1. **Secrets Management**:
   ```yaml
   # Use external secrets operator or Kubernetes secrets
   chromadbAdmin:
     config:
       secretKey: ""  # Set via environment variables
   
   # External secret example
   apiVersion: external-secrets.io/v1beta1
   kind: SecretStore
   metadata:
     name: vault-backend
   spec:
     provider:
       vault:
         server: "https://vault.company.com"
   ```

2. **Network Security**:
   ```yaml
   # Enable network policies
   networkPolicy:
     enabled: true
   
   # Use TLS everywhere
   ingress:
     tls:
       - secretName: chromadb-admin-tls
   ```

3. **RBAC**:
   ```yaml
   # Minimal service account permissions
   serviceAccount:
     create: true
     annotations:
       iam.gke.io/gcp-service-account: "chromadb-admin@project.iam.gserviceaccount.com"
   ```

### High Availability

1. **Multi-Zone Deployment**:
   ```yaml
   chromadbAdmin:
     affinity:
       podAntiAffinity:
         preferredDuringSchedulingIgnoredDuringExecution:
           - weight: 100
             podAffinityTerm:
               topologyKey: topology.kubernetes.io/zone
   ```

2. **Database HA**:
   ```yaml
   postgresql:
     architecture: replication
     readReplicas:
       replicaCount: 2
   ```

3. **Auto-scaling**:
   ```yaml
   autoscaling:
     enabled: true
     minReplicas: 3
     maxReplicas: 20
     behavior:
       scaleDown:
         stabilizationWindowSeconds: 300
   ```

### Monitoring & Observability

1. **Prometheus Integration**:
   ```yaml
   monitoring:
     serviceMonitor:
       enabled: true
       namespace: monitoring
   ```

2. **Logging**:
   ```yaml
   # Configure structured logging
   chromadbAdmin:
     extraEnvVars:
       - name: LOG_LEVEL
         value: "INFO"
       - name: LOG_FORMAT
         value: "json"
   ```

3. **Health Checks**:
   ```yaml
   chromadbAdmin:
     livenessProbe:
       initialDelaySeconds: 30
       periodSeconds: 10
     readinessProbe:
       initialDelaySeconds: 5
       periodSeconds: 5
   ```

### Backup & Recovery

1. **Database Backups**:
   ```yaml
   postgresql:
     backup:
       enabled: true
       cronjob:
         schedule: "0 2 * * *"
         storage:
           size: 100Gi
   ```

2. **ChromaDB Backups**:
   ```bash
   # Schedule regular backups of ChromaDB data
   kubectl create cronjob chromadb-backup \
     --image=your-backup-image \
     --schedule="0 3 * * *" \
     -- /backup-script.sh
   ```

## 🔧 Customization

### External Dependencies

#### External PostgreSQL
```yaml
postgresql:
  enabled: false

chromadbAdmin:
  config:
    databaseUrl: "postgresql://user:pass@external-postgres:5432/db"
```

#### External ChromaDB
```yaml
chromadb:
  enabled: false

chromadbAdmin:
  config:
    chromadbUrl: "http://external-chromadb:8000"
    chromadbToken: "auth-token"
```

### Custom Images

```yaml
chromadbAdmin:
  image:
    repository: your-registry.com/chromadb-admin
    tag: custom-v1.0.0
```

### Resource Tuning

```yaml
# For large deployments
chromadbAdmin:
  resources:
    requests:
      cpu: 1000m
      memory: 2Gi
    limits:
      cpu: 2000m
      memory: 4Gi

chromadb:
  resources:
    requests:
      cpu: 2000m
      memory: 4Gi
    limits:
      cpu: 4000m
      memory: 8Gi
```

## 🚀 Deployment Environments

### Development
- Single replica
- Small resource requests
- No ingress/TLS
- Local storage

### Staging
- 2 replicas
- Medium resources
- Basic ingress
- Persistent storage

### Production
- 5+ replicas
- Auto-scaling enabled
- Full security (TLS, network policies)
- High-performance storage
- Monitoring enabled
- Backup configured

## 📊 Monitoring & Troubleshooting

### Common Issues

1. **Pod Startup Issues**:
   ```bash
   kubectl logs -l app.kubernetes.io/name=chromadb-admin
   kubectl describe pod -l app.kubernetes.io/name=chromadb-admin
   ```

2. **Database Connection**:
   ```bash
   kubectl exec -it deployment/chromadb-admin-postgresql -- psql -U chromadb
   ```

3. **ChromaDB Health**:
   ```bash
   kubectl exec -it deployment/chromadb-admin-chromadb -- curl localhost:8000/api/v1/heartbeat
   ```

### Performance Tuning

1. **CPU/Memory Optimization**:
   ```yaml
   resources:
     requests:
       cpu: 500m      # Start here
       memory: 512Mi  # Monitor and adjust
   ```

2. **Storage Performance**:
   ```yaml
   persistence:
     storageClass: "fast-ssd"  # Use high-performance storage
   ```

3. **Network Optimization**:
   ```yaml
   service:
     type: ClusterIP  # For internal communication
     sessionAffinity: ClientIP  # For sticky sessions
   ```

## 🔒 Security Checklist

- [ ] Change default passwords
- [ ] Enable TLS/HTTPS
- [ ] Configure network policies
- [ ] Set resource limits
- [ ] Use non-root security context
- [ ] Enable pod security standards
- [ ] Regular security updates
- [ ] Backup encryption
- [ ] Access logging
- [ ] Regular security audits

## 📚 Additional Resources

- [Helm Chart README](helm/chromadb-admin/README.md)
- [Security Assessment Report](SECURITY_REPORT.md)
- [Application README](README.md)
- [GitHub Actions Documentation](.github/workflows/build-and-publish.yml)

## 🆘 Support

If you encounter issues:

1. Check the [troubleshooting section](#monitoring--troubleshooting)
2. Review application logs
3. Check the [GitHub Issues](https://github.com/yourusername/chromadb-admin/issues)
4. Join our [Discussions](https://github.com/yourusername/chromadb-admin/discussions) 
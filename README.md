# n8n EKS Operator

[![Go Report Card](https://goreportcard.com/badge/github.com/lxhiguera/n8n-eks-operator)](https://goreportcard.com/report/github.com/lxhiguera/n8n-eks-operator)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Release](https://img.shields.io/github/release/lxhiguera/n8n-eks-operator.svg)](https://github.com/lxhiguera/n8n-eks-operator/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/lxhiguera/n8n-eks-operator.svg)](https://hub.docker.com/r/lxhiguera/n8n-eks-operator)

A community-driven Kubernetes operator for managing n8n workflow automation instances on Amazon EKS with full AWS integration and enterprise features.

> **⚠️ Important Notice**: This is an **unofficial, community-maintained** operator for n8n. It is **not affiliated with or endorsed by n8n.io**. This project is developed and maintained independently by [@lxhiguera](https://github.com/lxhiguera).

## 🚀 Features

### Core Functionality
- **Complete n8n Lifecycle Management**: Deploy, scale, update, and monitor n8n instances
- **AWS Native Integration**: RDS PostgreSQL, ElastiCache Redis, S3 storage, CloudFront CDN
- **High Availability**: Multi-AZ deployments with automatic failover
- **Auto-scaling**: Horizontal Pod Autoscaler with custom metrics
- **Security First**: Pod Security Standards, Network Policies, RBAC, secrets encryption
- **Observability**: Prometheus metrics, Grafana dashboards, CloudWatch integration
- **Service Mesh Ready**: Istio integration with mTLS and traffic management
- **GitOps Compatible**: Declarative configuration with Kubernetes CRDs

### 🏢 Enterprise Features
- **Multi-Tenancy**: Complete tenant isolation with resource quotas and network policies
- **Single Sign-On (SSO)**: OIDC and SAML integration
- **Audit Logging**: Comprehensive audit trails for compliance
- **API Gateway**: Rate limiting and security controls
- **Role-Based Access Control**: Fine-grained permissions management
- **Compliance**: Built-in support for SOC2, GDPR, HIPAA standards
- **Data Governance**: Data classification and retention policies
- **Advanced Security**: Encryption, network isolation, and threat protection

## 📋 Prerequisites

- **Kubernetes**: 1.26+ (EKS recommended)
- **AWS CLI**: Configured with appropriate permissions
- **kubectl**: Latest version
- **Helm**: 3.8+ (for chart installation)

## 🚀 Quick Start

### 1. Install the Operator

#### Using Helm (Recommended)
```bash
# Add the Helm repository
helm repo add n8n-operator https://lxhiguera.github.io/n8n-eks-operator
helm repo update

# Install the operator
helm install n8n-operator n8n-operator/n8n-eks-operator \
  --namespace n8n-system \
  --create-namespace
```

#### Using kubectl
```bash
# Install CRDs and operator
kubectl apply -f https://github.com/lxhiguera/n8n-eks-operator/releases/latest/download/install.yaml
```

### 2. Create an n8n Instance

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: my-n8n
  namespace: default
spec:
  image: n8nio/n8n:latest
  replicas: 2
  
  # AWS Configuration
  aws:
    region: us-west-2
    
  # Database (RDS PostgreSQL)
  database:
    type: postgres
    postgres:
      host: my-rds-instance.region.rds.amazonaws.com
      database: n8n
      username: n8n_user
      passwordSecret:
        name: n8n-db-secret
        key: password
        
  # Cache (ElastiCache Redis)
  cache:
    type: redis
    redis:
      host: my-redis-cluster.cache.amazonaws.com
      
  # Storage (S3)
  storage:
    type: s3
    s3:
      bucket: my-n8n-storage
      region: us-west-2
      
  # Ingress
  ingress:
    enabled: true
    host: n8n.example.com
    tls:
      enabled: true
      certificateArn: arn:aws:acm:us-west-2:123456789012:certificate/12345678-1234-1234-1234-123456789012
```

Apply the configuration:
```bash
kubectl apply -f n8n-instance.yaml
```

### 3. Access n8n

```bash
# Check the status
kubectl get n8ninstance my-n8n

# Get the endpoint
kubectl describe n8ninstance my-n8n
```

## 🏢 Enterprise Features

### Multi-Tenancy Example

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: n8n-enterprise
spec:
  enterprise:
    enabled: true
    multiTenancy:
      enabled: true
      tenants:
        - id: dev-team
          name: Development Team
          resourceQuota:
            cpu: "2"
            memory: "4Gi"
          networkIsolation:
            enabled: true
        - id: prod-team
          name: Production Team
          resourceQuota:
            cpu: "4"
            memory: "8Gi"
          networkIsolation:
            enabled: true
    sso:
      enabled: true
      provider: oidc
      oidc:
        issuerUrl: https://auth.company.com
        clientId: n8n-enterprise
    auditLogging:
      enabled: true
      destinations: ["cloudwatch", "s3"]
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Enterprise Features](docs/enterprise-features.md)
- [Local Development](docs/local-development.md)
- [Troubleshooting](docs/troubleshooting.md)
- [API Reference](docs/api-reference.md)

## 🧪 Testing

### Local Testing
```bash
# Quick test (requires Go and Podman/Docker)
./scripts/test-operator.sh

# Full local Kubernetes test (requires kubectl + kind)
make local-setup
make local-deploy
make local-test
```

### Build from Source
```bash
# Clone the repository
git clone https://github.com/lxhiguera/n8n-eks-operator.git
cd n8n-eks-operator

# Build the operator
make build

# Run tests
make test

# Build container image
make docker-build
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   n8n Pods     │    │  Load Balancer  │    │   CloudFront    │
│                 │    │      (ALB)      │    │      (CDN)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │   EKS Cluster   │    │      Redis      │
│     (RDS)       │    │                 │    │  (ElastiCache)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   S3 Storage    │
                    │   (Workflows)   │
                    └─────────────────┘
```

## 🤝 Contributing

Contributions are welcome! This is a community project.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Setup local development environment
make local-setup

# Run tests
make test

# Build and test locally
make build
./scripts/test-operator.sh
```

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This operator is a community project and is not officially supported by n8n.io. Use at your own risk in production environments. Always test thoroughly before deploying to production.

## 🙏 Acknowledgments

- [n8n.io](https://n8n.io) for creating the amazing n8n workflow automation platform
- The Kubernetes community for the operator framework and best practices
- AWS for the comprehensive cloud services integration

## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/lxhiguera/n8n-eks-operator/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/lxhiguera/n8n-eks-operator/discussions)
- 📖 **Documentation**: [docs/](docs/)

---

**Made with ❤️ by [@lxhiguera](https://github.com/lxhiguera)**
# Enterprise Features

The n8n EKS Operator provides comprehensive enterprise features for organizations that need advanced security, compliance, and multi-tenancy capabilities.

## Overview

Enterprise features include:

- **Multi-Tenancy**: Isolated workspaces with resource quotas and network isolation
- **Single Sign-On (SSO)**: Integration with OIDC/SAML providers
- **Audit Logging**: Comprehensive audit trails for compliance
- **API Gateway**: Rate limiting and security controls
- **Compliance**: Built-in support for SOC2, GDPR, HIPAA standards
- **Advanced RBAC**: Fine-grained role-based access control
- **Data Governance**: Data classification and retention policies

## Enabling Enterprise Features

To enable enterprise features, set the `enterprise.enabled` field to `true` in your N8nInstance specification:

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: n8n-enterprise
spec:
  enterprise:
    enabled: true
    # Additional enterprise configuration...
```

## Multi-Tenancy

Multi-tenancy allows you to create isolated workspaces for different teams or departments within your organization.

### Configuration

```yaml
enterprise:
  multiTenancy:
    enabled: true
    tenants:
      - id: dev-team
        name: Development Team
        description: Development team workspace
        enabled: true
        
        # Resource quotas
        resourceQuota:
          cpu: "2"
          memory: "4Gi"
          storage: "50Gi"
          pods: 10
          services: 5
          
        # Network isolation
        networkIsolation:
          enabled: true
          subnetIsolation: true
          securityGroups:
            - sg-dev-team-n8n
            
        # User management
        userManagement:
          enabled: true
          authProvider: oidc
          ssoEnabled: true
          roleBasedAccess:
            enabled: true
            defaultRole: developer
            roles:
              - name: admin
                permissions:
                  - resource: workflows
                    actions: ["create", "read", "update", "delete", "execute"]
                    scope: "*"
```

### Features

- **Resource Isolation**: Each tenant gets dedicated CPU, memory, and storage quotas
- **Network Isolation**: Network policies prevent cross-tenant communication
- **Storage Isolation**: Dedicated S3 buckets with tenant-specific encryption keys
- **RBAC**: Tenant-specific roles and permissions
- **Separate Deployments**: Each tenant gets its own n8n deployment and services

### Tenant Access

Each tenant gets its own subdomain:
- `dev-team.n8n.company.com`
- `marketing.n8n.company.com`
- `production.n8n.company.com`

## Single Sign-On (SSO)

Integrate with your organization's identity provider for centralized authentication.

### OIDC Configuration

```yaml
enterprise:
  sso:
    enabled: true
    provider: oidc
    oidc:
      issuerUrl: https://auth.company.com
      clientId: n8n-enterprise
      clientSecret:
        name: n8n-oidc-secret
        key: client-secret
      scopes: ["openid", "profile", "email", "groups"]
      usernameClaim: preferred_username
      emailClaim: email
      groupsClaim: groups
```

### SAML Configuration

```yaml
enterprise:
  sso:
    enabled: true
    provider: saml
    saml:
      metadataUrl: https://auth.company.com/saml/metadata
      entityId: n8n-enterprise
      certificate:
        name: n8n-saml-cert
        key: certificate
```

### Supported Providers

- **OIDC**: Auth0, Okta, Azure AD, Google Workspace, Keycloak
- **SAML**: ADFS, Okta, OneLogin, PingIdentity

## Audit Logging

Comprehensive audit logging for compliance and security monitoring.

### Configuration

```yaml
enterprise:
  auditLogging:
    enabled: true
    level: detailed  # standard, detailed, verbose
    destinations:
      - cloudwatch
      - s3
      - elasticsearch
    retentionPeriod: "7y"
    encryptionEnabled: true
```

### Logged Events

- User authentication and authorization
- Workflow creation, modification, and execution
- Credential access and modification
- Administrative actions
- API access and rate limiting events
- Data access and modification

### Log Destinations

- **CloudWatch Logs**: Real-time log streaming to AWS CloudWatch
- **S3**: Long-term storage in encrypted S3 buckets
- **Elasticsearch**: Search and analysis capabilities
- **External SIEM**: Integration with security information and event management systems

## API Gateway

Built-in API gateway with rate limiting and security controls.

### Configuration

```yaml
enterprise:
  apiGateway:
    enabled: true
    rateLimiting:
      enabled: true
      rules:
        - path: "/api/*"
          limit: "100/minute"
          burst: 20
        - path: "/webhook/*"
          limit: "1000/minute"
          burst: 200
          
    authentication:
      enabled: true
      exemptPaths:
        - "/healthz"
        - "/webhook/*"
        
    securityHeaders:
      enabled: true
      headers:
        X-Frame-Options: DENY
        X-Content-Type-Options: nosniff
        X-XSS-Protection: "1; mode=block"
        Strict-Transport-Security: "max-age=31536000; includeSubDomains"
```

### Features

- **Rate Limiting**: Configurable rate limits per endpoint
- **Authentication**: Enforce authentication on API endpoints
- **Security Headers**: Automatic security header injection
- **Request/Response Logging**: Detailed API access logs
- **DDoS Protection**: Built-in protection against denial of service attacks

## Compliance

Built-in support for major compliance standards.

### Configuration

```yaml
enterprise:
  compliance:
    enabled: true
    standards:
      - SOC2
      - GDPR
      - HIPAA
      - PCI-DSS
      
    dataRetention:
      enabled: true
      defaultRetention: "3y"
      policies:
        - name: execution-logs
          dataType: execution_logs
          retention: "1y"
          action: archive
          
    dataClassification:
      enabled: true
      defaultLevel: internal
      levels:
        - name: public
          description: Public information
          color: green
          
        - name: confidential
          description: Confidential business information
          color: orange
          policies:
            - encryption-required
            
    privacyControls:
      enabled: true
      piiDetection: true
      dataMasking: true
      consentManagement: true
      rightToErasure: true
```

### Supported Standards

- **SOC 2**: System and Organization Controls
- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act
- **PCI-DSS**: Payment Card Industry Data Security Standard
- **ISO 27001**: Information Security Management

### Privacy Controls

- **PII Detection**: Automatic detection of personally identifiable information
- **Data Masking**: Automatic masking of sensitive data in logs and exports
- **Consent Management**: Track and manage user consent for data processing
- **Right to Erasure**: Automated data deletion upon request

## Role-Based Access Control (RBAC)

Fine-grained access control with custom roles and permissions.

### Role Configuration

```yaml
userManagement:
  roleBasedAccess:
    enabled: true
    defaultRole: user
    roles:
      - name: admin
        description: Full administrative access
        permissions:
          - resource: workflows
            actions: ["create", "read", "update", "delete", "execute"]
            scope: "*"
          - resource: credentials
            actions: ["create", "read", "update", "delete"]
            scope: "*"
          - resource: users
            actions: ["create", "read", "update", "delete"]
            scope: "*"
            
      - name: developer
        description: Developer access
        permissions:
          - resource: workflows
            actions: ["create", "read", "update", "delete", "execute"]
            scope: "own"
          - resource: credentials
            actions: ["create", "read", "update"]
            scope: "own"
            
      - name: viewer
        description: Read-only access
        permissions:
          - resource: workflows
            actions: ["read"]
            scope: "shared"
```

### Resources and Actions

- **workflows**: create, read, update, delete, execute, share
- **credentials**: create, read, update, delete, share
- **executions**: read, retry, delete
- **users**: create, read, update, delete, invite
- **settings**: read, update
- **monitoring**: read

### Scopes

- **\***: All resources
- **own**: Resources owned by the user
- **shared**: Resources shared with the user
- **team**: Resources within the user's team
- **tenant**: Resources within the user's tenant

## Data Governance

Comprehensive data governance and lifecycle management.

### Data Classification

Automatic and manual data classification with policy enforcement:

```yaml
dataClassification:
  enabled: true
  defaultLevel: internal
  levels:
    - name: public
      description: Public information
      color: green
      policies: []
      
    - name: internal
      description: Internal company information
      color: yellow
      policies:
        - internal-access-policy
        
    - name: confidential
      description: Confidential business information
      color: orange
      policies:
        - confidential-access-policy
        - encryption-required
        
    - name: restricted
      description: Highly sensitive information
      color: red
      policies:
        - restricted-access-policy
        - encryption-required
        - audit-required
        
  autoTagging: true
```

### Data Retention Policies

Automated data lifecycle management:

```yaml
dataRetention:
  enabled: true
  defaultRetention: "3y"
  policies:
    - name: execution-logs
      dataType: execution_logs
      retention: "1y"
      action: archive
      enabled: true
      
    - name: audit-logs
      dataType: audit_logs
      retention: "7y"
      action: retain
      enabled: true
      
    - name: user-data
      dataType: user_data
      retention: "5y"
      action: anonymize
      enabled: true
```

### Actions

- **retain**: Keep data as-is
- **archive**: Move to long-term storage
- **anonymize**: Remove personally identifiable information
- **delete**: Permanently delete data

## Security Features

### Encryption

- **Data at Rest**: All data encrypted using AWS KMS
- **Data in Transit**: TLS 1.3 for all communications
- **Tenant-Specific Keys**: Separate encryption keys per tenant

### Network Security

- **Network Policies**: Kubernetes network policies for traffic isolation
- **Security Groups**: AWS security groups for network-level access control
- **VPC Isolation**: Optional VPC-level isolation for tenants
- **Service Mesh**: Optional Istio service mesh integration

### Secrets Management

- **AWS Secrets Manager**: Integration with AWS Secrets Manager
- **Kubernetes Secrets**: Encrypted Kubernetes secrets
- **Credential Rotation**: Automatic credential rotation
- **Least Privilege**: Minimal required permissions

## Monitoring and Alerting

Enhanced monitoring for enterprise environments.

### Metrics

- **Business Metrics**: Workflow execution rates, success rates, error rates
- **Security Metrics**: Authentication failures, authorization violations
- **Compliance Metrics**: Data retention compliance, audit log completeness
- **Performance Metrics**: Response times, throughput, resource utilization

### Alerting

- **Security Alerts**: Suspicious activity, failed authentications
- **Compliance Alerts**: Policy violations, retention failures
- **Performance Alerts**: High error rates, slow response times
- **Operational Alerts**: Service failures, resource exhaustion

## Getting Started

1. **Enable Enterprise Features**: Set `enterprise.enabled: true`
2. **Configure SSO**: Set up integration with your identity provider
3. **Set Up Tenants**: Define tenant configurations if using multi-tenancy
4. **Configure Compliance**: Enable required compliance standards
5. **Set Up Monitoring**: Configure monitoring and alerting
6. **Test Access**: Verify SSO and RBAC configurations

## Best Practices

### Security

- Use separate encryption keys for each tenant
- Enable MFA for all administrative accounts
- Regularly rotate credentials and certificates
- Monitor audit logs for suspicious activity

### Compliance

- Define clear data classification policies
- Implement appropriate retention periods
- Regular compliance audits and reviews
- Document all compliance procedures

### Multi-Tenancy

- Plan resource quotas based on expected usage
- Use network isolation for sensitive tenants
- Implement proper backup and disaster recovery per tenant
- Monitor resource usage and adjust quotas as needed

### Performance

- Monitor API gateway performance and adjust rate limits
- Use appropriate resource quotas to prevent resource starvation
- Implement proper caching strategies
- Regular performance testing and optimization

## Troubleshooting

### Common Issues

1. **SSO Authentication Failures**
   - Verify OIDC/SAML configuration
   - Check client credentials
   - Validate certificate configurations

2. **Tenant Isolation Issues**
   - Verify network policies are applied
   - Check security group configurations
   - Validate RBAC permissions

3. **Audit Log Delivery Failures**
   - Check CloudWatch Logs permissions
   - Verify S3 bucket access
   - Validate log forwarding configuration

4. **Rate Limiting Issues**
   - Review rate limit configurations
   - Check API gateway logs
   - Adjust limits based on usage patterns

### Support

For enterprise support, contact your n8n representative or submit a support ticket through the enterprise portal.
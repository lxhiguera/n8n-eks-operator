# API Reference

This document provides a complete reference for the n8n EKS Operator API.

## Custom Resource Definitions

### N8nInstance

The `N8nInstance` custom resource defines a complete n8n deployment with all its components and dependencies.

#### API Version and Kind

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
```

#### Metadata

Standard Kubernetes metadata fields are supported:

```yaml
metadata:
  name: string          # Required: Name of the N8nInstance
  namespace: string     # Optional: Namespace (defaults to "default")
  labels: {}           # Optional: Labels for the resource
  annotations: {}      # Optional: Annotations for the resource
```

#### Spec

The `spec` field defines the desired state of the n8n instance.

##### Top-level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | n8n version to deploy |
| `domain` | string | No | Domain name for the n8n instance |
| `components` | [ComponentsSpec](#componentsspec) | Yes | Component configuration |
| `database` | [DatabaseSpec](#databasespec) | Yes | Database configuration |
| `cache` | [CacheSpec](#cachespec) | No | Cache configuration |
| `storage` | [StorageSpec](#storagespec) | Yes | Storage configuration |
| `networking` | [NetworkingSpec](#networkingspec) | No | Networking configuration |
| `monitoring` | [MonitoringSpec](#monitoringspec) | No | Monitoring configuration |
| `security` | [SecuritySpec](#securityspec) | No | Security configuration |
| `performance` | [PerformanceSpec](#performancespec) | No | Performance configuration |
| `backup` | [BackupSpec](#backupspec) | No | Backup configuration |

##### ComponentsSpec

Defines the configuration for n8n components (main, webhook, worker).

```yaml
components:
  main:        # MainComponentSpec
  webhook:     # WebhookComponentSpec  
  worker:      # WorkerComponentSpec
```

###### MainComponentSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `replicas` | int32 | No | Number of replicas (default: 1) |
| `port` | int32 | No | Port number (default: 5678) |
| `subdomain` | string | No | Subdomain for the component |
| `resources` | [ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#resourcerequirements-v1-core) | No | Resource requirements |
| `autoscaling` | [AutoscalingSpec](#autoscalingspec) | No | Autoscaling configuration |
| `podDisruptionBudget` | [PodDisruptionBudgetSpec](#poddisruptionbudgetspec) | No | PDB configuration |
| `securityContext` | [SecurityContext](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#securitycontext-v1-core) | No | Security context |
| `affinity` | [Affinity](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#affinity-v1-core) | No | Pod affinity |
| `nodeSelector` | map[string]string | No | Node selector |
| `tolerations` | [][Toleration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#toleration-v1-core) | No | Tolerations |
| `env` | [][EnvVar](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#envvar-v1-core) | No | Environment variables |
| `volumeMounts` | [][VolumeMount](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#volumemount-v1-core) | No | Volume mounts |
| `livenessProbe` | [Probe](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#probe-v1-core) | No | Liveness probe |
| `readinessProbe` | [Probe](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#probe-v1-core) | No | Readiness probe |
| `startupProbe` | [Probe](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#probe-v1-core) | No | Startup probe |

###### WebhookComponentSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `replicas` | int32 | No | Number of replicas (default: 1) |
| `port` | int32 | No | Port number (default: 5679) |
| `subdomain` | string | No | Subdomain for webhooks |
| `resources` | [ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#resourcerequirements-v1-core) | No | Resource requirements |
| `autoscaling` | [AutoscalingSpec](#autoscalingspec) | No | Autoscaling configuration |
| `timeout` | string | No | Webhook timeout (default: "30s") |
| `maxPayloadSize` | string | No | Maximum payload size (default: "10MB") |
| `rateLimit` | [RateLimitSpec](#ratelimitspec) | No | Rate limiting configuration |

###### WorkerComponentSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `replicas` | int32 | No | Number of replicas (default: 1) |
| `resources` | [ResourceRequirements](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#resourcerequirements-v1-core) | No | Resource requirements |
| `autoscaling` | [AutoscalingSpec](#autoscalingspec) | No | Autoscaling configuration |
| `concurrency` | int32 | No | Worker concurrency (default: 10) |
| `maxExecutionTime` | string | No | Max execution time (default: "1h") |
| `queue` | [QueueSpec](#queuespec) | No | Queue configuration |

##### AutoscalingSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `enabled` | bool | No | Enable autoscaling (default: false) |
| `minReplicas` | int32 | No | Minimum replicas (default: 1) |
| `maxReplicas` | int32 | No | Maximum replicas (default: 10) |
| `targetCPU` | int32 | No | Target CPU utilization % (default: 80) |
| `targetMemory` | int32 | No | Target memory utilization % |
| `behavior` | [HorizontalPodAutoscalerBehavior](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#horizontalpodautoscalerbehavior-v2-autoscaling) | No | HPA behavior |
| `customMetrics` | [][MetricSpec](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#metricspec-v2-autoscaling) | No | Custom metrics |

##### DatabaseSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Database type ("rds", "external") |
| `host` | string | Yes | Database host |
| `port` | int32 | Yes | Database port |
| `name` | string | Yes | Database name |
| `credentialsSecret` | string | Yes | Secret containing credentials |
| `ssl` | bool | No | Enable SSL (default: false) |
| `sslMode` | string | No | SSL mode ("disable", "require", "verify-ca", "verify-full") |
| `sslCert` | string | No | SSL certificate |
| `connectionPooling` | [ConnectionPoolingSpec](#connectionpoolingspec) | No | Connection pooling |
| `readReplicas` | [ReadReplicasSpec](#readreplicasspec) | No | Read replicas configuration |
| `migrations` | [MigrationsSpec](#migrationsspec) | No | Migration settings |
| `backup` | [DatabaseBackupSpec](#databasebackupspec) | No | Backup configuration |

##### CacheSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Cache type ("elasticache", "external") |
| `host` | string | Yes | Cache host |
| `port` | int32 | Yes | Cache port |
| `credentialsSecret` | string | No | Secret containing credentials |
| `ssl` | bool | No | Enable SSL (default: false) |
| `tlsSkipVerify` | bool | No | Skip TLS verification |
| `auth` | [CacheAuthSpec](#cacheauthspec) | No | Authentication configuration |
| `ttl` | [CacheTTLSpec](#cachettlspec) | No | TTL configuration |
| `cluster` | [CacheClusterSpec](#cacheclusterspec) | No | Cluster configuration |
| `keyPrefix` | string | No | Key prefix for multi-tenancy |
| `maxMemoryPolicy` | string | No | Memory eviction policy |
| `maxMemory` | string | No | Maximum memory |

##### StorageSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `s3` | [S3StorageSpec](#s3storagespec) | No | S3 storage configuration |
| `cloudfront` | [CloudFrontSpec](#cloudfrontspec) | No | CloudFront configuration |
| `persistent` | [PersistentStorageSpec](#persistentstoragespec) | No | Persistent volume configuration |

##### NetworkingSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `dns` | [DNSSpec](#dnsspec) | No | DNS configuration |
| `ssl` | [SSLSpec](#sslspec) | No | SSL configuration |
| `loadBalancer` | [LoadBalancerSpec](#loadbalancerspec) | No | Load balancer configuration |
| `istio` | [IstioSpec](#istiospec) | No | Istio service mesh configuration |

##### MonitoringSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `metrics` | [MetricsSpec](#metricsspec) | No | Metrics configuration |
| `logging` | [LoggingSpec](#loggingspec) | No | Logging configuration |
| `alerts` | [AlertsSpec](#alertsspec) | No | Alerting configuration |

##### SecuritySpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `podSecurityStandard` | string | No | Pod Security Standard ("privileged", "baseline", "restricted") |
| `networkPolicies` | [NetworkPoliciesSpec](#networkpoliciesspec) | No | Network policies configuration |
| `rbac` | [RBACSpec](#rbacspec) | No | RBAC configuration |
| `secrets` | [SecretsSpec](#secretsspec) | No | Secrets management configuration |
| `imageSecurity` | [ImageSecuritySpec](#imagesecurityspec) | No | Image security configuration |

#### Status

The `status` field shows the current state of the n8n instance.

##### N8nInstanceStatus

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase ("Pending", "Creating", "Ready", "Updating", "Deleting", "Failed") |
| `conditions` | [][Condition](#condition) | Detailed conditions |
| `componentStatus` | [ComponentStatus](#componentstatus) | Status of each component |
| `endpoints` | [EndpointsStatus](#endpointsstatus) | Service endpoints |
| `observedGeneration` | int64 | Last observed generation |
| `lastUpdateTime` | [Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta) | Last update timestamp |

##### Condition

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Condition type |
| `status` | string | Condition status ("True", "False", "Unknown") |
| `reason` | string | Reason for the condition |
| `message` | string | Human-readable message |
| `lastTransitionTime` | [Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#time-v1-meta) | Last transition time |

##### ComponentStatus

| Field | Type | Description |
|-------|------|-------------|
| `main` | [ComponentState](#componentstate) | Main component status |
| `webhook` | [ComponentState](#componentstate) | Webhook component status |
| `worker` | [ComponentState](#componentstate) | Worker component status |

##### ComponentState

| Field | Type | Description |
|-------|------|-------------|
| `ready` | bool | Component ready status |
| `replicas` | int32 | Current replicas |
| `readyReplicas` | int32 | Ready replicas |
| `conditions` | [][Condition](#condition) | Component conditions |

## Detailed Specifications

### ConnectionPoolingSpec

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable connection pooling |
| `maxConnections` | int32 | Maximum connections |
| `minConnections` | int32 | Minimum connections |
| `idleTimeout` | string | Idle timeout |
| `maxLifetime` | string | Maximum connection lifetime |
| `acquireTimeout` | string | Connection acquire timeout |

### ReadReplicasSpec

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable read replicas |
| `hosts` | []string | Read replica hosts |
| `loadBalancing` | string | Load balancing strategy |

### S3StorageSpec

| Field | Type | Description |
|-------|------|-------------|
| `bucket` | string | S3 bucket name |
| `region` | string | AWS region |
| `prefix` | string | Object key prefix |
| `encryption` | string | Encryption type |
| `kmsKeyId` | string | KMS key ID |
| `versioning` | bool | Enable versioning |
| `lifecyclePolicy` | string | Lifecycle policy |
| `replication` | [S3ReplicationSpec](#s3replicationspec) | Replication configuration |
| `corsConfiguration` | [CORSConfiguration](#corsconfiguration) | CORS configuration |

### MetricsSpec

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable metrics |
| `port` | int32 | Metrics port |
| `path` | string | Metrics path |
| `prometheus` | [PrometheusSpec](#prometheusspec) | Prometheus configuration |
| `cloudwatch` | [CloudWatchSpec](#cloudwatchspec) | CloudWatch configuration |

### LoggingSpec

| Field | Type | Description |
|-------|------|-------------|
| `level` | string | Log level |
| `format` | string | Log format |
| `cloudwatch` | [CloudWatchLogsSpec](#cloudwatchlogsspec) | CloudWatch Logs configuration |
| `fields` | []string | Structured logging fields |
| `sampling` | [LogSamplingSpec](#logsamplingspec) | Log sampling configuration |

### NetworkPoliciesSpec

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Enable network policies |
| `denyAll` | bool | Default deny all traffic |
| `allowRules` | [][NetworkPolicyRule](#networkpolicyrule) | Allow rules |

## Examples

### Basic N8nInstance

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: basic-n8n
  namespace: default
spec:
  version: "1.0.0"
  domain: "n8n.example.com"
  
  components:
    main:
      replicas: 2
      resources:
        requests:
          cpu: "200m"
          memory: "256Mi"
        limits:
          cpu: "1000m"
          memory: "1Gi"
    
    webhook:
      replicas: 1
    
    worker:
      replicas: 2
  
  database:
    type: "rds"
    host: "n8n-db.cluster-xxx.us-west-2.rds.amazonaws.com"
    port: 5432
    name: "n8n"
    credentialsSecret: "n8n-db-credentials"
    ssl: true
  
  storage:
    s3:
      bucket: "n8n-workflows"
      region: "us-west-2"
    persistent:
      storageClass: "gp3"
      size: "10Gi"
```

### Production N8nInstance with Full Configuration

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: production-n8n
  namespace: n8n-production
spec:
  version: "1.0.0"
  domain: "workflows.company.com"
  
  components:
    main:
      replicas: 3
      resources:
        requests:
          cpu: "500m"
          memory: "1Gi"
        limits:
          cpu: "2000m"
          memory: "4Gi"
      
      autoscaling:
        enabled: true
        minReplicas: 3
        maxReplicas: 10
        targetCPU: 70
      
      podDisruptionBudget:
        enabled: true
        minAvailable: 2
    
    webhook:
      replicas: 2
      autoscaling:
        enabled: true
        minReplicas: 2
        maxReplicas: 8
        targetCPU: 75
    
    worker:
      replicas: 5
      autoscaling:
        enabled: true
        minReplicas: 5
        maxReplicas: 20
        targetCPU: 80
  
  database:
    type: "rds"
    host: "n8n-prod.cluster-abc123.us-west-2.rds.amazonaws.com"
    port: 5432
    name: "n8n_production"
    credentialsSecret: "n8n-prod-db-credentials"
    ssl: true
    sslMode: "require"
    
    connectionPooling:
      enabled: true
      maxConnections: 100
      minConnections: 10
    
    readReplicas:
      enabled: true
      hosts:
        - "n8n-prod-ro-1.cluster-abc123.us-west-2.rds.amazonaws.com"
        - "n8n-prod-ro-2.cluster-abc123.us-west-2.rds.amazonaws.com"
  
  cache:
    type: "elasticache"
    host: "n8n-prod-redis.abc123.cache.amazonaws.com"
    port: 6379
    credentialsSecret: "n8n-prod-redis-credentials"
    ssl: true
    
    cluster:
      enabled: true
      nodes:
        - "n8n-prod-redis-001.abc123.cache.amazonaws.com:6379"
        - "n8n-prod-redis-002.abc123.cache.amazonaws.com:6379"
        - "n8n-prod-redis-003.abc123.cache.amazonaws.com:6379"
  
  storage:
    s3:
      bucket: "n8n-production-workflows"
      region: "us-west-2"
      encryption: "AES256"
      versioning: true
    
    cloudfront:
      enabled: true
      domain: "cdn.workflows.company.com"
      certificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/abc123"
    
    persistent:
      type: "ebs-csi"
      storageClass: "gp3"
      size: "100Gi"
      autoExpansion: true
  
  networking:
    dns:
      provider: "route53"
      zoneId: "Z123456789"
    
    ssl:
      provider: "acm"
      certificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/def456"
    
    istio:
      enabled: true
      gateway: "n8n-gateway"
      mtls:
        mode: "STRICT"
  
  monitoring:
    metrics:
      enabled: true
      prometheus:
        enabled: true
        serviceMonitor: true
      cloudwatch:
        enabled: true
        namespace: "N8N/Production"
    
    logging:
      level: "info"
      format: "json"
      cloudwatch:
        enabled: true
        logGroup: "/aws/eks/n8n-production"
        retention: 30
    
    alerts:
      enabled: true
      sns:
        topicArn: "arn:aws:sns:us-west-2:123456789012:n8n-alerts"
  
  security:
    podSecurityStandard: "restricted"
    
    networkPolicies:
      enabled: true
      denyAll: true
      allowRules:
        - name: "allow-database"
          ports:
            - port: 5432
              protocol: "TCP"
        - name: "allow-cache"
          ports:
            - port: 6379
              protocol: "TCP"
    
    rbac:
      enabled: true
    
    secrets:
      encryption: true
      rotation:
        enabled: true
        interval: "90d"
```

## Validation Rules

The operator enforces the following validation rules:

### Required Fields
- `spec.version` must be specified
- `spec.components.main` must be configured
- `spec.database` must be configured
- `spec.storage` must have at least one storage type configured

### Field Constraints
- `spec.components.main.replicas` must be >= 1
- `spec.components.webhook.replicas` must be >= 0
- `spec.components.worker.replicas` must be >= 0
- Database port must be between 1 and 65535
- Cache port must be between 1 and 65535

### Conditional Requirements
- If `spec.cache` is specified, `type` and `host` are required
- If `spec.networking.dns.provider` is "route53", `zoneId` is required
- If `spec.networking.ssl.provider` is "acm", `certificateArn` is required
- If autoscaling is enabled, `minReplicas` must be <= `maxReplicas`

### Immutable Fields
The following fields cannot be changed after creation:
- `spec.database.type`
- `spec.cache.type` (if specified)
- `spec.storage.s3.region`

## Status Conditions

The operator reports the following condition types in the status:

| Type | Description |
|------|-------------|
| `Ready` | Overall readiness of the N8nInstance |
| `DatabaseReady` | Database connectivity and readiness |
| `CacheReady` | Cache connectivity and readiness |
| `StorageReady` | Storage configuration and readiness |
| `ComponentsReady` | All components are ready |
| `NetworkingReady` | Networking configuration is ready |
| `MonitoringReady` | Monitoring is configured and ready |

## Events

The operator emits the following events:

| Type | Reason | Description |
|------|--------|-------------|
| `Normal` | `Created` | N8nInstance was created |
| `Normal` | `Updated` | N8nInstance was updated |
| `Normal` | `DatabaseConnected` | Database connection established |
| `Normal` | `CacheConnected` | Cache connection established |
| `Normal` | `ComponentReady` | Component became ready |
| `Warning` | `DatabaseConnectionFailed` | Failed to connect to database |
| `Warning` | `CacheConnectionFailed` | Failed to connect to cache |
| `Warning` | `ComponentNotReady` | Component is not ready |
| `Warning` | `ValidationFailed` | Configuration validation failed |

This API reference provides comprehensive documentation for all fields and their usage. For practical examples, see the `examples/` directory in the repository.
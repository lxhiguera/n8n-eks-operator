# Configuration Guide

This guide covers advanced configuration options for the n8n EKS Operator and N8nInstance resources.

## Operator Configuration

### Helm Values

The operator can be configured using Helm values. Here are the key configuration sections:

#### Basic Configuration

```yaml
# values.yaml
operator:
  replicaCount: 2
  image:
    registry: ghcr.io
    repository: lxhiguera/n8n-eks-operator
    tag: "v0.1.0"
    pullPolicy: IfNotPresent
  
  resources:
    limits:
      cpu: 1000m
      memory: 1Gi
    requests:
      cpu: 200m
      memory: 256Mi
  
  # Environment variables
  env:
    - name: LOG_LEVEL
      value: "info"
    - name: METRICS_BIND_ADDRESS
      value: ":8080"
    - name: HEALTH_PROBE_BIND_ADDRESS
      value: ":8081"
```

#### AWS Configuration

```yaml
aws:
  region: us-west-2
  cluster:
    name: my-eks-cluster
  
  # IRSA (IAM Roles for Service Accounts)
  serviceAccount:
    roleArn: arn:aws:iam::123456789012:role/n8n-operator-role
  
  # Default tags applied to all AWS resources
  defaultTags:
    Environment: production
    Project: n8n
    ManagedBy: n8n-eks-operator
```

#### Monitoring Configuration

```yaml
monitoring:
  enabled: true
  
  serviceMonitor:
    enabled: true
    namespace: monitoring
    interval: 30s
    scrapeTimeout: 10s
    labels:
      release: prometheus
  
  prometheusRule:
    enabled: true
    namespace: monitoring
    labels:
      release: prometheus
    rules:
      - alert: N8nOperatorDown
        expr: up{job="n8n-eks-operator"} == 0
        for: 5m
        labels:
          severity: critical
  
  grafanaDashboard:
    enabled: true
    namespace: monitoring
    labels:
      grafana_dashboard: "1"
```

#### Security Configuration

```yaml
security:
  podSecurityStandards:
    enforce: restricted
    audit: restricted
    warn: restricted
  
  networkPolicy:
    enabled: true
    ingress:
      - from:
        - namespaceSelector:
            matchLabels:
              name: kube-system
    egress:
      - to: []
        ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 6443
  
  rbac:
    create: true
    rules: []  # Additional custom rules
```

#### Webhook Configuration

```yaml
webhook:
  enabled: true
  
  certificate:
    # Use cert-manager for automatic certificate management
    certManager:
      enabled: true
      issuer: letsencrypt-prod
      duration: 8760h  # 1 year
      renewBefore: 720h  # 30 days
    
    # Or use custom certificates
    custom:
      enabled: false
      secretName: custom-webhook-certs
    
    # Or use self-signed certificates
    selfSigned:
      enabled: false
  
  mutatingWebhookConfiguration:
    enabled: true
    failurePolicy: Fail
    timeoutSeconds: 10
  
  validatingWebhookConfiguration:
    enabled: true
    failurePolicy: Fail
    timeoutSeconds: 10
```

## N8nInstance Configuration

### Basic Structure

```yaml
apiVersion: n8n.io/v1alpha1
kind: N8nInstance
metadata:
  name: my-n8n
  namespace: default
spec:
  version: "1.0.0"
  domain: "n8n.example.com"
  
  # Component configuration
  components: {}
  
  # External services
  database: {}
  cache: {}
  storage: {}
  
  # Networking
  networking: {}
  
  # Monitoring and observability
  monitoring: {}
  
  # Security settings
  security: {}
  
  # Performance and scaling
  performance: {}
```

### Component Configuration

#### Main Component (UI/API Server)

```yaml
components:
  main:
    replicas: 3
    port: 5678
    subdomain: "app"  # Creates app.n8n.example.com
    
    resources:
      requests:
        cpu: "500m"
        memory: "1Gi"
      limits:
        cpu: "2000m"
        memory: "4Gi"
    
    # Horizontal Pod Autoscaler
    autoscaling:
      enabled: true
      minReplicas: 3
      maxReplicas: 10
      targetCPU: 70
      targetMemory: 80
      
      # Advanced HPA behavior
      behavior:
        scaleUp:
          stabilizationWindowSeconds: 60
          policies:
          - type: Percent
            value: 100
            periodSeconds: 15
        scaleDown:
          stabilizationWindowSeconds: 300
          policies:
          - type: Percent
            value: 10
            periodSeconds: 60
    
    # Pod Disruption Budget
    podDisruptionBudget:
      enabled: true
      minAvailable: 2
    
    # Security context
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      runAsGroup: 1000
      fsGroup: 1000
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
      seccompProfile:
        type: RuntimeDefault
    
    # Pod placement
    affinity:
      podAntiAffinity:
        preferredDuringSchedulingIgnoredDuringExecution:
        - weight: 100
          podAffinityTerm:
            labelSelector:
              matchExpressions:
              - key: app.kubernetes.io/component
                operator: In
                values:
                - main
            topologyKey: topology.kubernetes.io/zone
    
    nodeSelector:
      node-type: "compute"
    
    tolerations:
    - key: "workload"
      operator: "Equal"
      value: "n8n"
      effect: "NoSchedule"
    
    # Environment variables
    env:
      - name: N8N_LOG_LEVEL
        value: "info"
      - name: N8N_METRICS
        value: "true"
      - name: N8N_DIAGNOSTICS_ENABLED
        value: "false"
      - name: N8N_VERSION_NOTIFICATIONS_ENABLED
        value: "false"
      - name: N8N_TEMPLATES_ENABLED
        value: "true"
      - name: N8N_USER_MANAGEMENT_DISABLED
        value: "false"
      - name: N8N_PUBLIC_API_DISABLED
        value: "false"
    
    # Volume mounts
    volumeMounts:
      - name: temp-storage
        mountPath: /tmp
      - name: cache-storage
        mountPath: /home/node/.cache
    
    # Probes
    livenessProbe:
      httpGet:
        path: /healthz
        port: 5678
      initialDelaySeconds: 30
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 3
    
    readinessProbe:
      httpGet:
        path: /healthz
        port: 5678
      initialDelaySeconds: 5
      periodSeconds: 5
      timeoutSeconds: 3
      failureThreshold: 3
    
    startupProbe:
      httpGet:
        path: /healthz
        port: 5678
      initialDelaySeconds: 10
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 30
```

#### Webhook Component

```yaml
components:
  webhook:
    replicas: 2
    port: 5679
    subdomain: "webhooks"
    
    resources:
      requests:
        cpu: "200m"
        memory: "256Mi"
      limits:
        cpu: "1000m"
        memory: "1Gi"
    
    autoscaling:
      enabled: true
      minReplicas: 2
      maxReplicas: 8
      targetCPU: 75
    
    # Webhook-specific configuration
    timeout: 30s
    maxPayloadSize: "10MB"
    
    # Rate limiting
    rateLimit:
      enabled: true
      requestsPerMinute: 1000
      burstSize: 100
```

#### Worker Component

```yaml
components:
  worker:
    replicas: 5
    
    resources:
      requests:
        cpu: "300m"
        memory: "512Mi"
      limits:
        cpu: "1500m"
        memory: "2Gi"
    
    autoscaling:
      enabled: true
      minReplicas: 5
      maxReplicas: 20
      targetCPU: 80
      targetMemory: 85
      
      # Custom metrics for worker scaling
      customMetrics:
        - type: Pods
          pods:
            metric:
              name: n8n_queue_depth
            target:
              type: AverageValue
              averageValue: "10"
    
    # Worker-specific configuration
    concurrency: 10
    maxExecutionTime: "1h"
    
    # Queue configuration
    queue:
      type: "redis"
      maxJobs: 1000
      jobTimeout: "30m"
      retryAttempts: 3
      retryDelay: "5s"
```

### Database Configuration

#### RDS PostgreSQL

```yaml
database:
  type: "rds"
  host: "n8n-db.cluster-xxx.us-west-2.rds.amazonaws.com"
  port: 5432
  name: "n8n_production"
  credentialsSecret: "n8n-db-credentials"
  
  # SSL configuration
  ssl: true
  sslMode: "require"
  sslCert: "rds-ca-2019-root.pem"
  
  # Connection pooling
  connectionPooling:
    enabled: true
    maxConnections: 100
    minConnections: 10
    idleTimeout: "30m"
    maxLifetime: "1h"
    acquireTimeout: "10s"
  
  # Read replicas for scaling
  readReplicas:
    enabled: true
    hosts:
      - "n8n-db-ro-1.cluster-xxx.us-west-2.rds.amazonaws.com"
      - "n8n-db-ro-2.cluster-xxx.us-west-2.rds.amazonaws.com"
    loadBalancing: "round-robin"
  
  # Migration settings
  migrations:
    enabled: true
    timeout: "10m"
    lockTimeout: "5m"
  
  # Backup configuration
  backup:
    enabled: true
    schedule: "0 2 * * *"
    retention: "30d"
```

#### External PostgreSQL

```yaml
database:
  type: "external"
  host: "external-postgres.company.com"
  port: 5432
  name: "n8n"
  credentialsSecret: "external-db-credentials"
  ssl: true
  
  # Custom connection parameters
  connectionParams:
    application_name: "n8n-production"
    connect_timeout: "10"
    statement_timeout: "30000"
```

### Cache Configuration

#### ElastiCache Redis

```yaml
cache:
  type: "elasticache"
  host: "n8n-redis.xxx.cache.amazonaws.com"
  port: 6379
  credentialsSecret: "n8n-redis-credentials"
  
  # SSL/TLS configuration
  ssl: true
  tlsSkipVerify: false
  
  # Authentication
  auth:
    enabled: true
    username: "n8n"
  
  # TTL configuration
  ttl:
    default: "1h"
    sessions: "24h"
    workflows: "30m"
    executions: "7d"
    cache: "5m"
  
  # Redis cluster configuration
  cluster:
    enabled: true
    nodes:
      - "n8n-redis-001.xxx.cache.amazonaws.com:6379"
      - "n8n-redis-002.xxx.cache.amazonaws.com:6379"
      - "n8n-redis-003.xxx.cache.amazonaws.com:6379"
    readTimeout: "3s"
    writeTimeout: "3s"
    dialTimeout: "5s"
    poolSize: 10
  
  # Key prefixes for multi-tenancy
  keyPrefix: "n8n:production:"
  
  # Memory management
  maxMemoryPolicy: "allkeys-lru"
  maxMemory: "1gb"
```

### Storage Configuration

#### S3 Storage

```yaml
storage:
  s3:
    bucket: "n8n-production-workflows"
    region: "us-west-2"
    prefix: "workflows/"
    
    # Encryption
    encryption: "AES256"
    kmsKeyId: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
    
    # Versioning and lifecycle
    versioning: true
    lifecyclePolicy: "30d"
    
    # Cross-region replication
    replication:
      enabled: true
      destinationBucket: "n8n-production-workflows-backup"
      destinationRegion: "us-east-1"
      storageClass: "STANDARD_IA"
    
    # Access control
    publicReadAccess: false
    corsConfiguration:
      allowedOrigins:
        - "https://n8n.example.com"
      allowedMethods:
        - "GET"
        - "POST"
        - "PUT"
      allowedHeaders:
        - "*"
      maxAgeSeconds: 3600
  
  # CloudFront CDN
  cloudfront:
    enabled: true
    domain: "cdn.n8n.example.com"
    certificateArn: "arn:aws:acm:us-east-1:123456789012:certificate/abc123"
    
    # Cache policies
    cachePolicies:
      default: "CachingOptimized"
      api: "CachingDisabled"
      assets: "CachingOptimizedForUncompressedObjects"
    
    # Custom behaviors
    behaviors:
      - pathPattern: "/assets/*"
        cachePolicy: "CachingOptimized"
        ttl: "1d"
        compress: true
      - pathPattern: "/api/*"
        cachePolicy: "CachingDisabled"
        allowedMethods:
          - "GET"
          - "HEAD"
          - "OPTIONS"
          - "PUT"
          - "POST"
          - "PATCH"
          - "DELETE"
    
    # Geographic restrictions
    geoRestriction:
      restrictionType: "whitelist"
      locations:
        - "US"
        - "CA"
        - "GB"
        - "DE"
  
  # Persistent volumes
  persistent:
    type: "ebs-csi"
    storageClass: "gp3"
    size: "100Gi"
    
    # Performance settings
    iops: 3000
    throughput: 125
    
    # Expansion and snapshots
    autoExpansion: true
    expandThreshold: 80  # Expand when 80% full
    
    snapshotPolicy: "daily"
    retentionDays: 30
    
    # Backup to S3
    backupToS3:
      enabled: true
      schedule: "0 3 * * *"
      bucket: "n8n-volume-backups"
```

### Networking Configuration

#### DNS and SSL

```yaml
networking:
  # DNS management
  dns:
    provider: "route53"
    zoneId: "Z123456789"
    ttl: 300
    
    # Health checks
    healthCheck:
      enabled: true
      path: "/healthz"
      interval: 30
      timeout: 5
      failureThreshold: 3
      regions:
        - "us-east-1"
        - "us-west-2"
        - "eu-west-1"
  
  # SSL/TLS configuration
  ssl:
    provider: "acm"
    certificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/def456"
    
    # TLS settings
    minTLSVersion: "1.2"
    cipherSuites:
      - "ECDHE-RSA-AES128-GCM-SHA256"
      - "ECDHE-RSA-AES256-GCM-SHA384"
      - "ECDHE-RSA-CHACHA20-POLY1305"
    
    # HSTS configuration
    hsts:
      enabled: true
      maxAge: 31536000
      includeSubdomains: true
      preload: true
  
  # Load balancer configuration
  loadBalancer:
    type: "application"
    scheme: "internet-facing"
    
    # Target group settings
    targetGroup:
      protocol: "HTTP"
      port: 80
      healthCheck:
        enabled: true
        path: "/healthz"
        interval: 30
        timeout: 5
        healthyThreshold: 2
        unhealthyThreshold: 3
        matcher: "200"
    
    # Listener configuration
    listeners:
      - port: 80
        protocol: "HTTP"
        redirectToHTTPS: true
      - port: 443
        protocol: "HTTPS"
        certificateArn: "arn:aws:acm:us-west-2:123456789012:certificate/def456"
    
    # Access logs
    accessLogs:
      enabled: true
      bucket: "n8n-alb-access-logs"
      prefix: "production"
```

#### Istio Service Mesh

```yaml
networking:
  istio:
    enabled: true
    
    # Gateway configuration
    gateway: "n8n-gateway"
    hosts:
      - "n8n.example.com"
      - "webhooks.n8n.example.com"
    
    # Virtual service configuration
    virtualService: true
    routes:
      - match:
          - uri:
              prefix: "/webhooks"
        route:
          - destination:
              host: "n8n-webhook-service"
              port:
                number: 5679
      - match:
          - uri:
              prefix: "/"
        route:
          - destination:
              host: "n8n-main-service"
              port:
                number: 5678
    
    # Destination rules
    destinationRule: true
    trafficPolicy:
      loadBalancer:
        simple: "LEAST_CONN"
      connectionPool:
        tcp:
          maxConnections: 100
        http:
          http1MaxPendingRequests: 50
          maxRequestsPerConnection: 10
      outlierDetection:
        consecutiveErrors: 3
        interval: "30s"
        baseEjectionTime: "30s"
    
    # mTLS configuration
    mtls:
      mode: "STRICT"
    
    # Authorization policies
    authorizationPolicies:
      - name: "allow-frontend"
        rules:
          - from:
            - source:
                principals:
                  - "cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"
      - name: "allow-internal"
        rules:
          - from:
            - source:
                namespaces:
                  - "n8n-system"
```

### Monitoring Configuration

#### Prometheus Metrics

```yaml
monitoring:
  metrics:
    enabled: true
    port: 9090
    path: "/metrics"
    
    # Prometheus configuration
    prometheus:
      enabled: true
      serviceMonitor: true
      interval: "30s"
      scrapeTimeout: "10s"
      
      # Metric relabeling
      metricRelabelings:
        - sourceLabels: [__name__]
          regex: "n8n_.*"
          targetLabel: "service"
          replacement: "n8n"
      
      # Custom metrics
      customMetrics:
        - name: "n8n_workflow_executions_total"
          help: "Total number of workflow executions"
          type: "counter"
          labels:
            - "workflow_id"
            - "status"
        - name: "n8n_workflow_execution_duration_seconds"
          help: "Workflow execution duration in seconds"
          type: "histogram"
          buckets: [0.1, 0.5, 1, 5, 10, 30, 60, 300, 600]
        - name: "n8n_active_workflows_total"
          help: "Number of active workflows"
          type: "gauge"
        - name: "n8n_queue_depth"
          help: "Number of jobs in the queue"
          type: "gauge"
    
    # CloudWatch integration
    cloudwatch:
      enabled: true
      namespace: "N8N/Production"
      region: "us-west-2"
      
      # Metric filters
      metricFilters:
        - filterName: "ErrorCount"
          filterPattern: "[timestamp, level=\"ERROR\", ...]"
          metricTransformation:
            metricName: "ErrorCount"
            metricNamespace: "N8N/Production"
            metricValue: "1"
        - filterName: "WorkflowExecutions"
          filterPattern: "[timestamp, level, component=\"worker\", message=\"Workflow executed\", ...]"
          metricTransformation:
            metricName: "WorkflowExecutions"
            metricNamespace: "N8N/Production"
            metricValue: "1"
```

#### Logging Configuration

```yaml
monitoring:
  logging:
    level: "info"
    format: "json"
    
    # CloudWatch Logs
    cloudwatch:
      enabled: true
      logGroup: "/aws/eks/n8n-production"
      retention: 30
      
      # Log streams per component
      streams:
        - name: "main"
          component: "main"
          logStreamPrefix: "main-"
        - name: "webhook"
          component: "webhook"
          logStreamPrefix: "webhook-"
        - name: "worker"
          component: "worker"
          logStreamPrefix: "worker-"
    
    # Structured logging fields
    fields:
      - "timestamp"
      - "level"
      - "component"
      - "workflowId"
      - "executionId"
      - "userId"
      - "message"
      - "duration"
      - "error"
    
    # Log sampling for high-volume logs
    sampling:
      enabled: true
      rate: 0.1  # Sample 10% of debug logs
      levels:
        - "debug"
    
    # Log forwarding to external systems
    forwarding:
      enabled: true
      destinations:
        - type: "elasticsearch"
          endpoint: "https://elasticsearch.company.com"
          index: "n8n-logs"
          auth:
            type: "basic"
            secretName: "elasticsearch-credentials"
        - type: "datadog"
          apiKey:
            secretName: "datadog-api-key"
            key: "api-key"
          site: "datadoghq.com"
          service: "n8n"
          source: "kubernetes"
```

### Security Configuration

#### Pod Security Standards

```yaml
security:
  podSecurityStandard: "restricted"
  
  # Custom security context
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    fsGroupChangePolicy: "OnRootMismatch"
    seccompProfile:
      type: "RuntimeDefault"
    supplementalGroups: []
  
  # Container security context
  containerSecurityContext:
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    capabilities:
      drop:
        - ALL
      add: []
    seccompProfile:
      type: "RuntimeDefault"
```

#### Network Policies

```yaml
security:
  networkPolicies:
    enabled: true
    denyAll: true
    
    # Ingress rules
    ingress:
      - name: "allow-ingress-controller"
        from:
          - namespaceSelector:
              matchLabels:
                name: "ingress-nginx"
        ports:
          - protocol: TCP
            port: 5678
          - protocol: TCP
            port: 5679
      
      - name: "allow-monitoring"
        from:
          - namespaceSelector:
              matchLabels:
                name: "monitoring"
        ports:
          - protocol: TCP
            port: 9090
    
    # Egress rules
    egress:
      - name: "allow-dns"
        to: []
        ports:
          - protocol: UDP
            port: 53
          - protocol: TCP
            port: 53
      
      - name: "allow-database"
        to:
          - namespaceSelector:
              matchLabels:
                name: "database"
        ports:
          - protocol: TCP
            port: 5432
      
      - name: "allow-cache"
        to:
          - namespaceSelector:
              matchLabels:
                name: "cache"
        ports:
          - protocol: TCP
            port: 6379
      
      - name: "allow-https"
        to: []
        ports:
          - protocol: TCP
            port: 443
```

#### RBAC Configuration

```yaml
security:
  rbac:
    enabled: true
    
    # Service account configuration
    serviceAccount:
      create: true
      name: "n8n-service-account"
      annotations:
        eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/n8n-role"
    
    # Custom roles
    roles:
      - name: "n8n-reader"
        rules:
          - apiGroups: [""]
            resources: ["pods", "services", "configmaps"]
            verbs: ["get", "list", "watch"]
          - apiGroups: ["apps"]
            resources: ["deployments", "replicasets"]
            verbs: ["get", "list", "watch"]
      
      - name: "n8n-writer"
        rules:
          - apiGroups: [""]
            resources: ["secrets"]
            verbs: ["get", "list", "create", "update", "patch"]
          - apiGroups: ["batch"]
            resources: ["jobs"]
            verbs: ["get", "list", "create", "delete"]
    
    # Role bindings
    roleBindings:
      - name: "n8n-reader-binding"
        roleRef:
          kind: "Role"
          name: "n8n-reader"
        subjects:
          - kind: "ServiceAccount"
            name: "n8n-service-account"
      
      - name: "n8n-writer-binding"
        roleRef:
          kind: "Role"
          name: "n8n-writer"
        subjects:
          - kind: "ServiceAccount"
            name: "n8n-service-account"
```

#### Secrets Management

```yaml
security:
  secrets:
    # Encryption at rest
    encryption: true
    encryptionKey: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
    
    # Automatic rotation
    rotation:
      enabled: true
      interval: "90d"
      
      # Rotation configuration per secret type
      database:
        interval: "30d"
        notificationTopic: "arn:aws:sns:us-west-2:123456789012:db-rotation"
      
      cache:
        interval: "60d"
        notificationTopic: "arn:aws:sns:us-west-2:123456789012:cache-rotation"
    
    # External secrets integration
    externalSecrets:
      enabled: true
      provider: "aws-secrets-manager"
      region: "us-west-2"
      
      # Secret mappings
      mappings:
        - secretName: "n8n-db-credentials"
          awsSecret: "n8n/production/database"
          refreshInterval: "1h"
        - secretName: "n8n-redis-credentials"
          awsSecret: "n8n/production/redis"
          refreshInterval: "1h"
        - secretName: "n8n-api-keys"
          awsSecret: "n8n/production/api-keys"
          refreshInterval: "15m"
```

This configuration guide covers the most important aspects of configuring both the operator and N8nInstance resources. For specific use cases, refer to the examples in the `examples/` directory.
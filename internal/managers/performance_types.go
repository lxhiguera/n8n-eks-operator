package managers

import "time"

// ResourceMetrics contains resource utilization metrics
type ResourceMetrics struct {
	Utilization float64   `json:"utilization"` // Percentage (0-100)
	Requests    float64   `json:"requests"`    // Requested amount
	Limits      float64   `json:"limits"`      // Limit amount
	Usage       float64   `json:"usage"`       // Current usage
	Available   float64   `json:"available"`   // Available amount
	Throttling  float64   `json:"throttling"`  // Throttling percentage
	LastUpdated time.Time `json:"lastUpdated"`
}

// NetworkMetrics contains network performance metrics
type NetworkMetrics struct {
	Latency     float64   `json:"latency"`     // Average latency in ms
	Throughput  float64   `json:"throughput"`  // Throughput in MB/s
	PacketLoss  float64   `json:"packetLoss"`  // Packet loss percentage
	Connections int64     `json:"connections"` // Active connections
	BytesIn     int64     `json:"bytesIn"`     // Bytes received
	BytesOut    int64     `json:"bytesOut"`    // Bytes sent
	ErrorRate   float64   `json:"errorRate"`   // Network error rate
	LastUpdated time.Time `json:"lastUpdated"`
}

// StorageMetrics contains storage performance metrics
type StorageMetrics struct {
	Utilization     float64   `json:"utilization"`     // Storage utilization %
	ReadLatency     float64   `json:"readLatency"`     // Read latency in ms
	WriteLatency    float64   `json:"writeLatency"`    // Write latency in ms
	ReadIOPS        float64   `json:"readIOPS"`        // Read IOPS
	WriteIOPS       float64   `json:"writeIOPS"`       // Write IOPS
	ReadThroughput  float64   `json:"readThroughput"`  // Read throughput MB/s
	WriteThroughput float64   `json:"writeThroughput"` // Write throughput MB/s
	QueueDepth      float64   `json:"queueDepth"`      // Average queue depth
	LastUpdated     time.Time `json:"lastUpdated"`
}

// DatabaseMetrics contains database performance metrics
type DatabaseMetrics struct {
	ConnectionUtilization float64   `json:"connectionUtilization"` // Connection pool utilization %
	QueryLatency          float64   `json:"queryLatency"`          // Average query latency in ms
	TransactionRate       float64   `json:"transactionRate"`       // Transactions per second
	LockWaitTime          float64   `json:"lockWaitTime"`          // Average lock wait time in ms
	DeadlockRate          float64   `json:"deadlockRate"`          // Deadlocks per second
	CacheHitRate          float64   `json:"cacheHitRate"`          // Database cache hit rate %
	ReplicationLag        float64   `json:"replicationLag"`        // Replication lag in ms
	ActiveConnections     int64     `json:"activeConnections"`     // Number of active connections
	SlowQueries           int64     `json:"slowQueries"`           // Number of slow queries
	LastUpdated           time.Time `json:"lastUpdated"`
}

// CacheMetrics contains cache performance metrics
type CacheMetrics struct {
	HitRate           float64   `json:"hitRate"`           // Cache hit rate %
	MissRate          float64   `json:"missRate"`          // Cache miss rate %
	Latency           float64   `json:"latency"`           // Average latency in ms
	MemoryUtilization float64   `json:"memoryUtilization"` // Memory utilization %
	KeyCount          int64     `json:"keyCount"`          // Number of keys
	Operations        int64     `json:"operations"`        // Operations per second
	Evictions         int64     `json:"evictions"`         // Number of evictions
	Connections       int64     `json:"connections"`       // Active connections
	LastUpdated       time.Time `json:"lastUpdated"`
}

// ApplicationMetrics contains application-specific performance metrics
type ApplicationMetrics struct {
	ResponseTime       float64   `json:"responseTime"`       // Average response time in ms
	Throughput         float64   `json:"throughput"`         // Requests per second
	ErrorRate          float64   `json:"errorRate"`          // Error rate %
	ActiveSessions     int64     `json:"activeSessions"`     // Number of active sessions
	WorkflowExecutions int64     `json:"workflowExecutions"` // Workflow executions per minute
	QueueLength        int64     `json:"queueLength"`        // Job queue length
	ProcessingTime     float64   `json:"processingTime"`     // Average processing time in ms
	MemoryLeaks        int64     `json:"memoryLeaks"`        // Detected memory leaks
	LastUpdated        time.Time `json:"lastUpdated"`
}

// KubernetesMetrics contains Kubernetes-specific metrics
type KubernetesMetrics struct {
	PodRestarts       int64     `json:"podRestarts"`       // Number of pod restarts
	PodReadiness      float64   `json:"podReadiness"`      // Pod readiness %
	NodeUtilization   float64   `json:"nodeUtilization"`   // Node utilization %
	SchedulingLatency float64   `json:"schedulingLatency"` // Pod scheduling latency in ms
	APILatency        float64   `json:"apiLatency"`        // Kubernetes API latency in ms
	EventRate         float64   `json:"eventRate"`         // Events per minute
	LastUpdated       time.Time `json:"lastUpdated"`
}

// PerformanceBottleneck represents a performance bottleneck
type PerformanceBottleneck struct {
	ID          string             `json:"id"`
	Component   string             `json:"component"`
	Type        BottleneckType     `json:"type"`
	Severity    SeverityLevel      `json:"severity"`
	Description string             `json:"description"`
	Impact      string             `json:"impact"`
	Metrics     map[string]float64 `json:"metrics"`
	DetectedAt  time.Time          `json:"detectedAt"`
	Duration    time.Duration      `json:"duration"`
}

// BottleneckType represents the type of bottleneck
type BottleneckType string

const (
	BottleneckTypeCPU      BottleneckType = "cpu"
	BottleneckTypeMemory   BottleneckType = "memory"
	BottleneckTypeNetwork  BottleneckType = "network"
	BottleneckTypeStorage  BottleneckType = "storage"
	BottleneckTypeDatabase BottleneckType = "database"
	BottleneckTypeCache    BottleneckType = "cache"
)

// SeverityLevel represents the severity of a bottleneck
type SeverityLevel string

const (
	SeverityLevelLow      SeverityLevel = "low"
	SeverityLevelMedium   SeverityLevel = "medium"
	SeverityLevelHigh     SeverityLevel = "high"
	SeverityLevelCritical SeverityLevel = "critical"
)

// PerformanceRecommendation represents a performance recommendation
type PerformanceRecommendation struct {
	ID              string                 `json:"id"`
	Type            RecommendationType     `json:"type"`
	Priority        RecommendationPriority `json:"priority"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Rationale       string                 `json:"rationale"`
	ExpectedImpact  *ImpactEstimate        `json:"expectedImpact"`
	Implementation  string                 `json:"implementation"`
	Prerequisites   []string               `json:"prerequisites"`
	RiskAssessment  string                 `json:"riskAssessment"`
	TimeToImplement string                 `json:"timeToImplement"`
	CreatedAt       time.Time              `json:"createdAt"`
}

// RecommendationType represents the type of recommendation
type RecommendationType string

const (
	RecommendationTypeScaling       RecommendationType = "scaling"
	RecommendationTypeConfiguration RecommendationType = "configuration"
	RecommendationTypeArchitecture  RecommendationType = "architecture"
	RecommendationTypeOptimization  RecommendationType = "optimization"
	RecommendationTypeMaintenance   RecommendationType = "maintenance"
)

// RecommendationPriority represents the priority of a recommendation
type RecommendationPriority string

const (
	RecommendationPriorityLow      RecommendationPriority = "low"
	RecommendationPriorityMedium   RecommendationPriority = "medium"
	RecommendationPriorityHigh     RecommendationPriority = "high"
	RecommendationPriorityCritical RecommendationPriority = "critical"
)

// PerformanceTrends contains performance trend data
type PerformanceTrends struct {
	TimeRange        string                     `json:"timeRange"`
	CPUTrend         *TrendData                 `json:"cpuTrend"`
	MemoryTrend      *TrendData                 `json:"memoryTrend"`
	NetworkTrend     *TrendData                 `json:"networkTrend"`
	StorageTrend     *TrendData                 `json:"storageTrend"`
	DatabaseTrend    *TrendData                 `json:"databaseTrend"`
	CacheTrend       *TrendData                 `json:"cacheTrend"`
	ApplicationTrend *TrendData                 `json:"applicationTrend"`
	Predictions      map[string]*PredictionData `json:"predictions"`
	LastUpdated      time.Time                  `json:"lastUpdated"`
}

// TrendData represents trend information for a metric
type TrendData struct {
	Direction   TrendDirection `json:"direction"`
	Slope       float64        `json:"slope"`
	Correlation float64        `json:"correlation"`
	Volatility  float64        `json:"volatility"`
	DataPoints  []DataPoint    `json:"dataPoints"`
	Forecast    []DataPoint    `json:"forecast"`
}

// TrendDirection represents the direction of a trend
type TrendDirection string

const (
	TrendDirectionIncreasing TrendDirection = "increasing"
	TrendDirectionDecreasing TrendDirection = "decreasing"
	TrendDirectionStable     TrendDirection = "stable"
	TrendDirectionVolatile   TrendDirection = "volatile"
)

// DataPoint represents a single data point in a trend
type DataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// PredictionData represents prediction information
type PredictionData struct {
	Metric          string    `json:"metric"`
	PredictedValue  float64   `json:"predictedValue"`
	Confidence      float64   `json:"confidence"`
	TimeHorizon     string    `json:"timeHorizon"`
	PredictionModel string    `json:"predictionModel"`
	Factors         []string  `json:"factors"`
	CreatedAt       time.Time `json:"createdAt"`
}

// PerformanceAlert represents a performance alert
type PerformanceAlert struct {
	ID           string            `json:"id"`
	Type         AlertType         `json:"type"`
	Severity     SeverityLevel     `json:"severity"`
	Component    string            `json:"component"`
	Metric       string            `json:"metric"`
	Threshold    float64           `json:"threshold"`
	CurrentValue float64           `json:"currentValue"`
	Message      string            `json:"message"`
	Actions      []string          `json:"actions"`
	CreatedAt    time.Time         `json:"createdAt"`
	ResolvedAt   *time.Time        `json:"resolvedAt,omitempty"`
	Metadata     map[string]string `json:"metadata"`
}

// AlertType represents the type of alert
type AlertType string

const (
	AlertTypeThreshold AlertType = "threshold"
	AlertTypeAnomaly   AlertType = "anomaly"
	AlertTypeTrend     AlertType = "trend"
	AlertTypeComposite AlertType = "composite"
)

// PerformanceProfile represents a performance profile for an instance
type PerformanceProfile struct {
	ID             string                   `json:"id"`
	Name           string                   `json:"name"`
	Description    string                   `json:"description"`
	InstanceType   string                   `json:"instanceType"`
	Workload       WorkloadType             `json:"workload"`
	ResourceLimits map[string]ResourceLimit `json:"resourceLimits"`
	Optimizations  []Optimization           `json:"optimizations"`
	Thresholds     map[string]float64       `json:"thresholds"`
	CreatedAt      time.Time                `json:"createdAt"`
	UpdatedAt      time.Time                `json:"updatedAt"`
}

// WorkloadType represents the type of workload
type WorkloadType string

const (
	WorkloadTypeCPUIntensive     WorkloadType = "cpu-intensive"
	WorkloadTypeMemoryIntensive  WorkloadType = "memory-intensive"
	WorkloadTypeIOIntensive      WorkloadType = "io-intensive"
	WorkloadTypeNetworkIntensive WorkloadType = "network-intensive"
	WorkloadTypeBalanced         WorkloadType = "balanced"
)

// ResourceLimit represents a resource limit
type ResourceLimit struct {
	Min     float64 `json:"min"`
	Max     float64 `json:"max"`
	Default float64 `json:"default"`
	Unit    string  `json:"unit"`
}

// PerformanceReport represents a comprehensive performance report
type PerformanceReport struct {
	ID              string                      `json:"id"`
	InstanceName    string                      `json:"instanceName"`
	Namespace       string                      `json:"namespace"`
	ReportType      ReportType                  `json:"reportType"`
	TimeRange       TimeRange                   `json:"timeRange"`
	GeneratedAt     time.Time                   `json:"generatedAt"`
	Summary         *PerformanceSummary         `json:"summary"`
	Metrics         *PerformanceMetrics         `json:"metrics"`
	Analysis        *PerformanceAnalysis        `json:"analysis"`
	Trends          *PerformanceTrends          `json:"trends"`
	Recommendations []PerformanceRecommendation `json:"recommendations"`
	Alerts          []PerformanceAlert          `json:"alerts"`
	Metadata        map[string]string           `json:"metadata"`
}

// ReportType represents the type of performance report
type ReportType string

const (
	ReportTypeDaily   ReportType = "daily"
	ReportTypeWeekly  ReportType = "weekly"
	ReportTypeMonthly ReportType = "monthly"
	ReportTypeCustom  ReportType = "custom"
)

// TimeRange represents a time range for reports
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// PerformanceSummary represents a summary of performance metrics
type PerformanceSummary struct {
	OverallScore         float64            `json:"overallScore"`
	ComponentScores      map[string]float64 `json:"componentScores"`
	TotalBottlenecks     int                `json:"totalBottlenecks"`
	CriticalIssues       int                `json:"criticalIssues"`
	OptimizationsApplied int                `json:"optimizationsApplied"`
	PerformanceGrade     string             `json:"performanceGrade"`
	KeyInsights          []string           `json:"keyInsights"`
}

// AutoTuningConfig represents auto-tuning configuration
type AutoTuningConfig struct {
	Enabled            bool                `json:"enabled"`
	Mode               AutoTuningMode      `json:"mode"`
	Aggressiveness     AggressivenessLevel `json:"aggressiveness"`
	SafetyChecks       bool                `json:"safetyChecks"`
	RollbackOnFailure  bool                `json:"rollbackOnFailure"`
	MaxOptimizations   int                 `json:"maxOptimizations"`
	OptimizationWindow string              `json:"optimizationWindow"`
	ExcludedComponents []string            `json:"excludedComponents"`
	CustomRules        []AutoTuningRule    `json:"customRules"`
	NotificationConfig *NotificationConfig `json:"notificationConfig"`
}

// AutoTuningMode represents the auto-tuning mode
type AutoTuningMode string

const (
	AutoTuningModeConservative AutoTuningMode = "conservative"
	AutoTuningModeBalanced     AutoTuningMode = "balanced"
	AutoTuningModeAggressive   AutoTuningMode = "aggressive"
	AutoTuningModeCustom       AutoTuningMode = "custom"
)

// AggressivenessLevel represents the aggressiveness level
type AggressivenessLevel string

const (
	AggressivenessLevelLow    AggressivenessLevel = "low"
	AggressivenessLevelMedium AggressivenessLevel = "medium"
	AggressivenessLevelHigh   AggressivenessLevel = "high"
)

// AutoTuningRule represents a custom auto-tuning rule
type AutoTuningRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Condition  string                 `json:"condition"`
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
	Priority   int                    `json:"priority"`
}

// NotificationConfig represents notification configuration
type NotificationConfig struct {
	Enabled      bool     `json:"enabled"`
	Channels     []string `json:"channels"`
	WebhookURL   string   `json:"webhookUrl"`
	SlackChannel string   `json:"slackChannel"`
	EmailList    []string `json:"emailList"`
}

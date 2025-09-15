/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//go:build security
// +build security

package security

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SecurityConfig holds configuration for security tests
type SecurityConfig struct {
	// Test execution settings
	TestTimeout time.Duration
	
	// Vulnerability scanning settings
	MaxCriticalVulnerabilities int
	MaxHighVulnerabilities     int
	MaxMediumVulnerabilities   int
	VulnerabilityScanTimeout   time.Duration
	
	// Compliance settings
	SOC2Required   bool
	GDPRRequired   bool
	HIPAARequired  bool
	PCIDSSRequired bool
	CISRequired    bool
	
	// Security scanning settings
	OperatorImage           string
	ScanContainerImages     bool
	ScanDependencies        bool
	RequireSignedImages     bool
	
	// Network security settings
	RequireNetworkPolicies  bool
	RequireDefaultDenyAll   bool
	AllowedEgressPorts      []int
	AllowedIngressPorts     []int
	
	// Pod security settings
	RequireNonRoot          bool
	RequireReadOnlyRoot     bool
	RequireResourceLimits   bool
	RequireSecurityContext  bool
	ForbidPrivileged        bool
	ForbidPrivilegeEscalation bool
	
	// RBAC settings
	RequireMinimalRBAC      bool
	ForbidClusterAdmin      bool
	RequireServiceAccount   bool
	
	// Encryption settings
	RequireEncryptionAtRest bool
	RequireEncryptionInTransit bool
	RequireTLSMinVersion    string
	
	// Audit and logging settings
	RequireAuditLogging     bool
	AuditLogRetentionDays   int
	SecurityLogRetentionDays int
	RequireLogIntegrity     bool
	
	// Secret management settings
	RequireSecretEncryption bool
	RequireSecretRotation   bool
	SecretRotationInterval  time.Duration
	
	// Monitoring and alerting settings
	RequireSecurityMonitoring bool
	RequireSecurityAlerts     bool
	AlertingEndpoints         []string
}

// NewSecurityConfig creates a new security test configuration
func NewSecurityConfig() *SecurityConfig {
	config := &SecurityConfig{
		// Default values
		TestTimeout:                30 * time.Minute,
		MaxCriticalVulnerabilities: 0,
		MaxHighVulnerabilities:     5,
		MaxMediumVulnerabilities:   20,
		VulnerabilityScanTimeout:   10 * time.Minute,
		
		// Compliance defaults
		SOC2Required:   true,
		GDPRRequired:   true,
		HIPAARequired:  false,
		PCIDSSRequired: false,
		CISRequired:    true,
		
		// Security scanning defaults
		ScanContainerImages: true,
		ScanDependencies:    true,
		RequireSignedImages: false,
		
		// Network security defaults
		RequireNetworkPolicies: true,
		RequireDefaultDenyAll:  true,
		AllowedEgressPorts:     []int{53, 443, 5432, 6379}, // DNS, HTTPS, PostgreSQL, Redis
		AllowedIngressPorts:    []int{5678, 5679},          // n8n main, webhook
		
		// Pod security defaults
		RequireNonRoot:               true,
		RequireReadOnlyRoot:          true,
		RequireResourceLimits:        true,
		RequireSecurityContext:       true,
		ForbidPrivileged:             true,
		ForbidPrivilegeEscalation:    true,
		
		// RBAC defaults
		RequireMinimalRBAC:    true,
		ForbidClusterAdmin:    true,
		RequireServiceAccount: true,
		
		// Encryption defaults
		RequireEncryptionAtRest:    true,
		RequireEncryptionInTransit: true,
		RequireTLSMinVersion:       "1.2",
		
		// Audit and logging defaults
		RequireAuditLogging:      true,
		AuditLogRetentionDays:    365,
		SecurityLogRetentionDays: 90,
		RequireLogIntegrity:      true,
		
		// Secret management defaults
		RequireSecretEncryption: true,
		RequireSecretRotation:   true,
		SecretRotationInterval:  90 * 24 * time.Hour, // 90 days
		
		// Monitoring defaults
		RequireSecurityMonitoring: true,
		RequireSecurityAlerts:     true,
		AlertingEndpoints:         []string{},
	}
	
	// Load from environment variables
	config.loadFromEnv()
	
	return config
}

// loadFromEnv loads configuration from environment variables
func (c *SecurityConfig) loadFromEnv() {
	// Test execution settings
	if val := os.Getenv("SEC_TEST_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.TestTimeout = duration
		}
	}
	
	// Vulnerability scanning settings
	if val := os.Getenv("SEC_MAX_CRITICAL_VULNS"); val != "" {
		if num, err := strconv.Atoi(val); err == nil {
			c.MaxCriticalVulnerabilities = num
		}
	}
	
	if val := os.Getenv("SEC_MAX_HIGH_VULNS"); val != "" {
		if num, err := strconv.Atoi(val); err == nil {
			c.MaxHighVulnerabilities = num
		}
	}
	
	if val := os.Getenv("SEC_MAX_MEDIUM_VULNS"); val != "" {
		if num, err := strconv.Atoi(val); err == nil {
			c.MaxMediumVulnerabilities = num
		}
	}
	
	if val := os.Getenv("SEC_VULN_SCAN_TIMEOUT"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.VulnerabilityScanTimeout = duration
		}
	}
	
	// Compliance settings
	if val := os.Getenv("SEC_SOC2_REQUIRED"); val != "" {
		c.SOC2Required = val == "true"
	}
	
	if val := os.Getenv("SEC_GDPR_REQUIRED"); val != "" {
		c.GDPRRequired = val == "true"
	}
	
	if val := os.Getenv("SEC_HIPAA_REQUIRED"); val != "" {
		c.HIPAARequired = val == "true"
	}
	
	if val := os.Getenv("SEC_PCIDSS_REQUIRED"); val != "" {
		c.PCIDSSRequired = val == "true"
	}
	
	if val := os.Getenv("SEC_CIS_REQUIRED"); val != "" {
		c.CISRequired = val == "true"
	}
	
	// Security scanning settings
	if val := os.Getenv("SEC_OPERATOR_IMAGE"); val != "" {
		c.OperatorImage = val
	}
	
	if val := os.Getenv("SEC_SCAN_CONTAINER_IMAGES"); val != "" {
		c.ScanContainerImages = val == "true"
	}
	
	if val := os.Getenv("SEC_SCAN_DEPENDENCIES"); val != "" {
		c.ScanDependencies = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_SIGNED_IMAGES"); val != "" {
		c.RequireSignedImages = val == "true"
	}
	
	// Network security settings
	if val := os.Getenv("SEC_REQUIRE_NETWORK_POLICIES"); val != "" {
		c.RequireNetworkPolicies = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_DEFAULT_DENY_ALL"); val != "" {
		c.RequireDefaultDenyAll = val == "true"
	}
	
	if val := os.Getenv("SEC_ALLOWED_EGRESS_PORTS"); val != "" {
		ports := strings.Split(val, ",")
		c.AllowedEgressPorts = make([]int, 0, len(ports))
		for _, port := range ports {
			if num, err := strconv.Atoi(strings.TrimSpace(port)); err == nil {
				c.AllowedEgressPorts = append(c.AllowedEgressPorts, num)
			}
		}
	}
	
	if val := os.Getenv("SEC_ALLOWED_INGRESS_PORTS"); val != "" {
		ports := strings.Split(val, ",")
		c.AllowedIngressPorts = make([]int, 0, len(ports))
		for _, port := range ports {
			if num, err := strconv.Atoi(strings.TrimSpace(port)); err == nil {
				c.AllowedIngressPorts = append(c.AllowedIngressPorts, num)
			}
		}
	}
	
	// Pod security settings
	if val := os.Getenv("SEC_REQUIRE_NON_ROOT"); val != "" {
		c.RequireNonRoot = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_READONLY_ROOT"); val != "" {
		c.RequireReadOnlyRoot = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_RESOURCE_LIMITS"); val != "" {
		c.RequireResourceLimits = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_SECURITY_CONTEXT"); val != "" {
		c.RequireSecurityContext = val == "true"
	}
	
	if val := os.Getenv("SEC_FORBID_PRIVILEGED"); val != "" {
		c.ForbidPrivileged = val == "true"
	}
	
	if val := os.Getenv("SEC_FORBID_PRIVILEGE_ESCALATION"); val != "" {
		c.ForbidPrivilegeEscalation = val == "true"
	}
	
	// RBAC settings
	if val := os.Getenv("SEC_REQUIRE_MINIMAL_RBAC"); val != "" {
		c.RequireMinimalRBAC = val == "true"
	}
	
	if val := os.Getenv("SEC_FORBID_CLUSTER_ADMIN"); val != "" {
		c.ForbidClusterAdmin = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_SERVICE_ACCOUNT"); val != "" {
		c.RequireServiceAccount = val == "true"
	}
	
	// Encryption settings
	if val := os.Getenv("SEC_REQUIRE_ENCRYPTION_AT_REST"); val != "" {
		c.RequireEncryptionAtRest = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_ENCRYPTION_IN_TRANSIT"); val != "" {
		c.RequireEncryptionInTransit = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_TLS_MIN_VERSION"); val != "" {
		c.RequireTLSMinVersion = val
	}
	
	// Audit and logging settings
	if val := os.Getenv("SEC_REQUIRE_AUDIT_LOGGING"); val != "" {
		c.RequireAuditLogging = val == "true"
	}
	
	if val := os.Getenv("SEC_AUDIT_LOG_RETENTION_DAYS"); val != "" {
		if num, err := strconv.Atoi(val); err == nil {
			c.AuditLogRetentionDays = num
		}
	}
	
	if val := os.Getenv("SEC_SECURITY_LOG_RETENTION_DAYS"); val != "" {
		if num, err := strconv.Atoi(val); err == nil {
			c.SecurityLogRetentionDays = num
		}
	}
	
	if val := os.Getenv("SEC_REQUIRE_LOG_INTEGRITY"); val != "" {
		c.RequireLogIntegrity = val == "true"
	}
	
	// Secret management settings
	if val := os.Getenv("SEC_REQUIRE_SECRET_ENCRYPTION"); val != "" {
		c.RequireSecretEncryption = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_SECRET_ROTATION"); val != "" {
		c.RequireSecretRotation = val == "true"
	}
	
	if val := os.Getenv("SEC_SECRET_ROTATION_INTERVAL"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			c.SecretRotationInterval = duration
		}
	}
	
	// Monitoring settings
	if val := os.Getenv("SEC_REQUIRE_SECURITY_MONITORING"); val != "" {
		c.RequireSecurityMonitoring = val == "true"
	}
	
	if val := os.Getenv("SEC_REQUIRE_SECURITY_ALERTS"); val != "" {
		c.RequireSecurityAlerts = val == "true"
	}
	
	if val := os.Getenv("SEC_ALERTING_ENDPOINTS"); val != "" {
		c.AlertingEndpoints = strings.Split(val, ",")
		for i, endpoint := range c.AlertingEndpoints {
			c.AlertingEndpoints[i] = strings.TrimSpace(endpoint)
		}
	}
}

// Validate validates the security configuration
func (c *SecurityConfig) Validate() error {
	if c.TestTimeout <= 0 {
		return fmt.Errorf("test timeout must be positive")
	}
	
	if c.MaxCriticalVulnerabilities < 0 {
		return fmt.Errorf("max critical vulnerabilities cannot be negative")
	}
	
	if c.MaxHighVulnerabilities < 0 {
		return fmt.Errorf("max high vulnerabilities cannot be negative")
	}
	
	if c.VulnerabilityScanTimeout <= 0 {
		return fmt.Errorf("vulnerability scan timeout must be positive")
	}
	
	if c.RequireTLSMinVersion != "" {
		validVersions := []string{"1.0", "1.1", "1.2", "1.3"}
		valid := false
		for _, version := range validVersions {
			if c.RequireTLSMinVersion == version {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid TLS minimum version: %s", c.RequireTLSMinVersion)
		}
	}
	
	if c.AuditLogRetentionDays < 0 {
		return fmt.Errorf("audit log retention days cannot be negative")
	}
	
	if c.SecurityLogRetentionDays < 0 {
		return fmt.Errorf("security log retention days cannot be negative")
	}
	
	if c.SecretRotationInterval <= 0 {
		return fmt.Errorf("secret rotation interval must be positive")
	}
	
	return nil
}

// GetSecurityProfiles returns predefined security profiles
func (c *SecurityConfig) GetSecurityProfiles() map[string]SecurityProfile {
	return map[string]SecurityProfile{
		"basic": {
			Name:        "Basic Security",
			Description: "Basic security requirements for development environments",
			Config: SecurityConfig{
				MaxCriticalVulnerabilities: 0,
				MaxHighVulnerabilities:     10,
				RequireNonRoot:             true,
				RequireResourceLimits:      true,
				RequireNetworkPolicies:     false,
				RequireAuditLogging:        false,
				SOC2Required:               false,
				GDPRRequired:               false,
				CISRequired:                false,
			},
		},
		"standard": {
			Name:        "Standard Security",
			Description: "Standard security requirements for staging environments",
			Config: SecurityConfig{
				MaxCriticalVulnerabilities: 0,
				MaxHighVulnerabilities:     5,
				RequireNonRoot:             true,
				RequireReadOnlyRoot:        true,
				RequireResourceLimits:      true,
				RequireNetworkPolicies:     true,
				RequireAuditLogging:        true,
				RequireSecretEncryption:    true,
				SOC2Required:               true,
				GDPRRequired:               true,
				CISRequired:                true,
			},
		},
		"strict": {
			Name:        "Strict Security",
			Description: "Strict security requirements for production environments",
			Config: SecurityConfig{
				MaxCriticalVulnerabilities: 0,
				MaxHighVulnerabilities:     0,
				RequireNonRoot:             true,
				RequireReadOnlyRoot:        true,
				RequireResourceLimits:      true,
				RequireSecurityContext:     true,
				RequireNetworkPolicies:     true,
				RequireDefaultDenyAll:      true,
				RequireAuditLogging:        true,
				RequireLogIntegrity:        true,
				RequireSecretEncryption:    true,
				RequireSecretRotation:      true,
				RequireSignedImages:        true,
				SOC2Required:               true,
				GDPRRequired:               true,
				CISRequired:                true,
			},
		},
		"compliance": {
			Name:        "Full Compliance",
			Description: "Full compliance requirements for regulated environments",
			Config: SecurityConfig{
				MaxCriticalVulnerabilities: 0,
				MaxHighVulnerabilities:     0,
				RequireNonRoot:             true,
				RequireReadOnlyRoot:        true,
				RequireResourceLimits:      true,
				RequireSecurityContext:     true,
				RequireNetworkPolicies:     true,
				RequireDefaultDenyAll:      true,
				RequireAuditLogging:        true,
				RequireLogIntegrity:        true,
				RequireSecretEncryption:    true,
				RequireSecretRotation:      true,
				RequireSignedImages:        true,
				RequireEncryptionAtRest:    true,
				RequireEncryptionInTransit: true,
				SOC2Required:               true,
				GDPRRequired:               true,
				HIPAARequired:              true,
				PCIDSSRequired:             true,
				CISRequired:                true,
			},
		},
	}
}

// SecurityProfile defines a security profile
type SecurityProfile struct {
	Name        string
	Description string
	Config      SecurityConfig
}

// GetComplianceRequirements returns compliance requirements for different standards
func (c *SecurityConfig) GetComplianceRequirements() map[string]ComplianceRequirement {
	return map[string]ComplianceRequirement{
		"SOC2": {
			Name:        "SOC 2 Type II",
			Description: "Service Organization Control 2 Type II compliance",
			Requirements: []string{
				"Access controls and authentication",
				"System monitoring and logging",
				"Data encryption in transit and at rest",
				"Incident response procedures",
				"Change management processes",
			},
			MandatoryControls: []string{
				"RequireAuditLogging",
				"RequireEncryptionInTransit",
				"RequireMinimalRBAC",
				"RequireSecurityMonitoring",
			},
		},
		"GDPR": {
			Name:        "General Data Protection Regulation",
			Description: "EU General Data Protection Regulation compliance",
			Requirements: []string{
				"Data protection by design and by default",
				"Data subject rights implementation",
				"Data breach notification procedures",
				"Data protection impact assessments",
				"Privacy-preserving technologies",
			},
			MandatoryControls: []string{
				"RequireEncryptionAtRest",
				"RequireEncryptionInTransit",
				"RequireAuditLogging",
				"RequireLogIntegrity",
			},
		},
		"CIS": {
			Name:        "CIS Kubernetes Benchmark",
			Description: "Center for Internet Security Kubernetes Benchmark",
			Requirements: []string{
				"RBAC configuration",
				"Pod Security Standards",
				"Network policies",
				"Audit logging",
				"Resource quotas and limits",
			},
			MandatoryControls: []string{
				"RequireMinimalRBAC",
				"RequireNonRoot",
				"RequireNetworkPolicies",
				"RequireResourceLimits",
				"ForbidPrivileged",
			},
		},
	}
}

// ComplianceRequirement defines a compliance requirement
type ComplianceRequirement struct {
	Name              string
	Description       string
	Requirements      []string
	MandatoryControls []string
}

// GetSecurityTestCategories returns security test categories
func (c *SecurityConfig) GetSecurityTestCategories() []SecurityTestCategory {
	return []SecurityTestCategory{
		{
			Name:        "Secret Management",
			Description: "Tests for secret encryption, rotation, and access control",
			Tests: []string{
				"TestSecretEncryption",
				"TestSecretRotation",
				"TestSecretAccessControl",
			},
		},
		{
			Name:        "Network Security",
			Description: "Tests for network policies and isolation",
			Tests: []string{
				"TestNetworkPolicies",
				"TestNetworkIsolation",
				"TestDefaultDenyAll",
			},
		},
		{
			Name:        "RBAC Security",
			Description: "Tests for role-based access control",
			Tests: []string{
				"TestRBACConfiguration",
				"TestMinimalPermissions",
				"TestPrivilegeEscalationPrevention",
			},
		},
		{
			Name:        "Pod Security",
			Description: "Tests for pod security standards",
			Tests: []string{
				"TestPodSecurityStandards",
				"TestNonRootExecution",
				"TestSecurityContexts",
				"TestResourceLimits",
			},
		},
		{
			Name:        "Vulnerability Management",
			Description: "Tests for vulnerability scanning and management",
			Tests: []string{
				"TestVulnerabilityScanning",
				"TestImageScanning",
				"TestDependencyScanning",
			},
		},
		{
			Name:        "Compliance",
			Description: "Tests for regulatory compliance",
			Tests: []string{
				"TestSOC2Compliance",
				"TestGDPRCompliance",
				"TestCISCompliance",
			},
		},
		{
			Name:        "Audit and Monitoring",
			Description: "Tests for security auditing and monitoring",
			Tests: []string{
				"TestSecurityAuditing",
				"TestSecurityMonitoring",
				"TestSecurityAlerting",
			},
		},
	}
}

// SecurityTestCategory defines a category of security tests
type SecurityTestCategory struct {
	Name        string
	Description string
	Tests       []string
}

// IsComplianceRequired checks if a specific compliance standard is required
func (c *SecurityConfig) IsComplianceRequired(standard string) bool {
	switch strings.ToUpper(standard) {
	case "SOC2":
		return c.SOC2Required
	case "GDPR":
		return c.GDPRRequired
	case "HIPAA":
		return c.HIPAARequired
	case "PCIDSS", "PCI-DSS":
		return c.PCIDSSRequired
	case "CIS":
		return c.CISRequired
	default:
		return false
	}
}

// GetRequiredSecurityControls returns a list of required security controls
func (c *SecurityConfig) GetRequiredSecurityControls() []string {
	var controls []string
	
	if c.RequireNonRoot {
		controls = append(controls, "non-root-execution")
	}
	if c.RequireReadOnlyRoot {
		controls = append(controls, "read-only-root-filesystem")
	}
	if c.RequireResourceLimits {
		controls = append(controls, "resource-limits")
	}
	if c.RequireSecurityContext {
		controls = append(controls, "security-context")
	}
	if c.ForbidPrivileged {
		controls = append(controls, "no-privileged-containers")
	}
	if c.ForbidPrivilegeEscalation {
		controls = append(controls, "no-privilege-escalation")
	}
	if c.RequireNetworkPolicies {
		controls = append(controls, "network-policies")
	}
	if c.RequireDefaultDenyAll {
		controls = append(controls, "default-deny-all")
	}
	if c.RequireMinimalRBAC {
		controls = append(controls, "minimal-rbac")
	}
	if c.RequireEncryptionAtRest {
		controls = append(controls, "encryption-at-rest")
	}
	if c.RequireEncryptionInTransit {
		controls = append(controls, "encryption-in-transit")
	}
	if c.RequireAuditLogging {
		controls = append(controls, "audit-logging")
	}
	if c.RequireSecretEncryption {
		controls = append(controls, "secret-encryption")
	}
	if c.RequireSecretRotation {
		controls = append(controls, "secret-rotation")
	}
	
	return controls
}
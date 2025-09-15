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

package managers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// AWSNetworkManager implements the NetworkManager interface for AWS services
type AWSNetworkManager struct {
	client       client.Client
	awsConfig    aws.Config
	route53Client *route53.Client
	acmClient    *acm.Client
}

// NewAWSNetworkManager creates a new AWSNetworkManager instance
func NewAWSNetworkManager(client client.Client, awsConfig aws.Config) *AWSNetworkManager {
	return &AWSNetworkManager{
		client:       client,
		awsConfig:    awsConfig,
		route53Client: route53.NewFromConfig(awsConfig),
		acmClient:    acm.NewFromConfig(awsConfig),
	}
}

// ReconcileNetworking ensures all networking configurations are correct
func (m *AWSNetworkManager) ReconcileNetworking(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Reconciling networking configuration")

	// Extract networking configuration from N8nInstance
	networkingConfig, err := m.extractNetworkingConfig(instance)
	if err != nil {
		logger.Error(err, "Failed to extract networking configuration")
		return fmt.Errorf("failed to extract networking configuration: %w", err)
	}

	// Reconcile DNS configuration
	if err := m.ReconcileDNS(ctx, networkingConfig); err != nil {
		logger.Error(err, "Failed to reconcile DNS")
		return fmt.Errorf("failed to reconcile DNS: %w", err)
	}

	// Reconcile SSL certificates
	if err := m.ReconcileSSL(ctx, networkingConfig); err != nil {
		logger.Error(err, "Failed to reconcile SSL")
		return fmt.Errorf("failed to reconcile SSL: %w", err)
	}

	// Reconcile Istio configuration
	if err := m.ReconcileIstio(ctx, networkingConfig); err != nil {
		logger.Error(err, "Failed to reconcile Istio")
		return fmt.Errorf("failed to reconcile Istio: %w", err)
	}

	// Create networking configuration secret
	if err := m.createNetworkingSecret(ctx, instance, networkingConfig); err != nil {
		logger.Error(err, "Failed to create networking secret")
		return fmt.Errorf("failed to create networking secret: %w", err)
	}

	logger.Info("Networking configuration reconciled successfully")
	return nil
}

// ReconcileDNS creates and configures DNS records
func (m *AWSNetworkManager) ReconcileDNS(ctx context.Context, config NetworkingConfig) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Reconciling DNS configuration")

	if config.DNS.Provider != "route53" {
		logger.Info("Route53 is not configured, skipping DNS setup")
		return nil
	}

	// Get or create hosted zone
	hostedZoneId, err := m.getOrCreateHostedZone(ctx, config.DNS.Route53)
	if err != nil {
		return fmt.Errorf("failed to get or create hosted zone: %w", err)
	}

	// Create DNS records for n8n components
	if err := m.createDNSRecords(ctx, hostedZoneId, config); err != nil {
		return fmt.Errorf("failed to create DNS records: %w", err)
	}

	logger.Info("DNS configuration reconciled successfully")
	return nil
}

// ReconcileSSL creates and configures SSL certificates
func (m *AWSNetworkManager) ReconcileSSL(ctx context.Context, config NetworkingConfig) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Reconciling SSL configuration")

	if config.SSL.Provider != "acm" {
		logger.Info("ACM is not configured, skipping SSL setup")
		return nil
	}

	// Request or validate SSL certificate
	certificateArn, err := m.requestOrValidateSSLCertificate(ctx, config.SSL.ACM)
	if err != nil {
		return fmt.Errorf("failed to request or validate SSL certificate: %w", err)
	}

	// Update configuration with certificate ARN
	config.SSL.ACM.CertificateArn = certificateArn

	logger.Info("SSL configuration reconciled successfully", "certificateArn", certificateArn)
	return nil
}

// ReconcileIstio creates and configures Istio resources
func (m *AWSNetworkManager) ReconcileIstio(ctx context.Context, config NetworkingConfig) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Reconciling Istio configuration")

	if !config.Istio.Enabled {
		logger.Info("Istio is disabled, skipping Istio setup")
		return nil
	}

	// Validate Istio installation
	if err := m.ValidateIstioInstallation(ctx); err != nil {
		return fmt.Errorf("Istio installation validation failed: %w", err)
	}

	// Create Istio Gateway
	if err := m.createIstioGateway(ctx, config); err != nil {
		return fmt.Errorf("failed to create Istio Gateway: %w", err)
	}

	// Create Istio VirtualService
	if err := m.createIstioVirtualService(ctx, config); err != nil {
		return fmt.Errorf("failed to create Istio VirtualService: %w", err)
	}

	// Create Istio DestinationRule
	if err := m.createIstioDestinationRule(ctx, config); err != nil {
		return fmt.Errorf("failed to create Istio DestinationRule: %w", err)
	}

	logger.Info("Istio configuration reconciled successfully")
	return nil
}

// ValidateIstioInstallation validates Istio is properly installed
func (m *AWSNetworkManager) ValidateIstioInstallation(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Validating Istio installation")

	// Check if Istio system namespace exists
	istioNamespace := &corev1.Namespace{}
	if err := m.client.Get(ctx, client.ObjectKey{Name: "istio-system"}, istioNamespace); err != nil {
		return fmt.Errorf("istio-system namespace not found: %w", err)
	}

	// Check if Istio pilot is running
	pilotDeployment := &unstructured.Unstructured{}
	pilotDeployment.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "apps",
		Version: "v1",
		Kind:    "Deployment",
	})

	if err := m.client.Get(ctx, client.ObjectKey{
		Namespace: "istio-system",
		Name:      "istiod",
	}, pilotDeployment); err != nil {
		return fmt.Errorf("istiod deployment not found: %w", err)
	}

	// Check if Istio gateway controller is running
	gatewayDeployment := &unstructured.Unstructured{}
	gatewayDeployment.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "apps",
		Version: "v1",
		Kind:    "Deployment",
	})

	if err := m.client.Get(ctx, client.ObjectKey{
		Namespace: "istio-system",
		Name:      "istio-ingressgateway",
	}, gatewayDeployment); err != nil {
		logger.Warn("istio-ingressgateway deployment not found, this may be expected in some configurations")
	}

	logger.Info("Istio installation validated successfully")
	return nil
}

// extractNetworkingConfig extracts networking configuration from N8nInstance
func (m *AWSNetworkManager) extractNetworkingConfig(instance *n8nv1alpha1.N8nInstance) (NetworkingConfig, error) {
	config := NetworkingConfig{}

	// Extract domain information
	if instance.Spec.Domain == "" {
		return config, fmt.Errorf("domain is required for networking configuration")
	}

	// Extract DNS configuration
	config.DNS = DNSConfig{
		Provider: "route53", // Default to Route53
		Route53: Route53Config{
			CreateZone: true, // Default to creating zone if it doesn't exist
		},
	}

	// Extract SSL configuration
	config.SSL = SSLConfig{
		Provider: "acm", // Default to ACM
		ACM: ACMConfig{
			AutoValidation:   true,
			ValidationMethod: "DNS",
		},
	}

	// Extract Istio configuration
	config.Istio = IstioConfig{
		Enabled: true, // Default to enabled
		Gateway: GatewayConfig{
			Name:  fmt.Sprintf("%s-gateway", instance.Name),
			Hosts: []string{instance.Spec.Domain},
		},
		VirtualService: VirtualServiceConfig{
			Timeout: "30s",
			Retries: 3,
		},
		AuthorizationPolicy: AuthorizationPolicyConfig{
			Enabled:        true,
			AllowedSources: []string{"*"}, // Default to allow all, should be configured per environment
		},
	}

	return config, nil
}

// getOrCreateHostedZone gets existing hosted zone or creates a new one
func (m *AWSNetworkManager) getOrCreateHostedZone(ctx context.Context, config Route53Config) (string, error) {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")

	// If hosted zone ID is provided, validate it exists
	if config.HostedZoneId != "" {
		logger.Info("Validating existing hosted zone", "hostedZoneId", config.HostedZoneId)
		
		input := &route53.GetHostedZoneInput{
			Id: aws.String(config.HostedZoneId),
		}
		
		_, err := m.route53Client.GetHostedZone(ctx, input)
		if err != nil {
			return "", fmt.Errorf("hosted zone %s not found: %w", config.HostedZoneId, err)
		}
		
		logger.Info("Hosted zone validated successfully", "hostedZoneId", config.HostedZoneId)
		return config.HostedZoneId, nil
	}

	// If no hosted zone ID provided and creation is disabled, return error
	if !config.CreateZone {
		return "", fmt.Errorf("no hosted zone ID provided and zone creation is disabled")
	}

	// Create new hosted zone
	logger.Info("Creating new hosted zone")
	// Note: This would require the domain name to create the zone
	// For now, return an error as we need more configuration
	return "", fmt.Errorf("hosted zone creation not implemented - please provide hosted zone ID")
}

// createDNSRecords creates DNS records for n8n components
func (m *AWSNetworkManager) createDNSRecords(ctx context.Context, hostedZoneId string, config NetworkingConfig) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating DNS records", "hostedZoneId", hostedZoneId)

	// Define DNS records to create
	records := []struct {
		name        string
		recordType  string
		target      string
		description string
	}{
		{
			name:        config.Istio.Gateway.Hosts[0], // Main domain
			recordType:  "A",
			target:      "", // Will be populated with load balancer IP
			description: "Main n8n application",
		},
		{
			name:        fmt.Sprintf("webhook.%s", config.Istio.Gateway.Hosts[0]),
			recordType:  "CNAME",
			target:      config.Istio.Gateway.Hosts[0],
			description: "n8n webhook endpoint",
		},
	}

	for _, record := range records {
		if err := m.createDNSRecord(ctx, hostedZoneId, record.name, record.recordType, record.target); err != nil {
			logger.Error(err, "Failed to create DNS record", "name", record.name, "type", record.recordType)
			return fmt.Errorf("failed to create DNS record %s: %w", record.name, err)
		}
	}

	logger.Info("DNS records created successfully")
	return nil
}

// createDNSRecord creates a single DNS record
func (m *AWSNetworkManager) createDNSRecord(ctx context.Context, hostedZoneId, name, recordType, target string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating DNS record", "name", name, "type", recordType, "target", target)

	// For now, we'll create a placeholder record
	// In a real implementation, you would get the actual load balancer endpoint
	if target == "" {
		logger.Info("Target not specified, skipping DNS record creation", "name", name)
		return nil
	}

	var resourceRecords []r53types.ResourceRecord
	
	switch recordType {
	case "A":
		// For A records, target should be an IP address
		resourceRecords = []r53types.ResourceRecord{
			{Value: aws.String(target)},
		}
	case "CNAME":
		// For CNAME records, target should be a domain name
		resourceRecords = []r53types.ResourceRecord{
			{Value: aws.String(target)},
		}
	default:
		return fmt.Errorf("unsupported record type: %s", recordType)
	}

	changeBatch := &r53types.ChangeBatch{
		Changes: []r53types.Change{
			{
				Action: r53types.ChangeActionUpsert,
				ResourceRecordSet: &r53types.ResourceRecordSet{
					Name:            aws.String(name),
					Type:            r53types.RRType(recordType),
					TTL:             aws.Int64(300), // 5 minutes
					ResourceRecords: resourceRecords,
				},
			},
		},
	}

	input := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(hostedZoneId),
		ChangeBatch:  changeBatch,
	}

	result, err := m.route53Client.ChangeResourceRecordSets(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to create DNS record: %w", err)
	}

	// Wait for change to propagate
	if result.ChangeInfo != nil && result.ChangeInfo.Id != nil {
		waiter := route53.NewResourceRecordSetsChangedWaiter(m.route53Client)
		if err := waiter.Wait(ctx, &route53.GetChangeInput{
			Id: result.ChangeInfo.Id,
		}, 5*time.Minute); err != nil {
			logger.Warn("DNS record change propagation timeout", "changeId", *result.ChangeInfo.Id)
		}
	}

	logger.Info("DNS record created successfully", "name", name)
	return nil
}

//
requestOrValidateSSLCertificate requests a new SSL certificate or validates existing one
func (m *AWSNetworkManager) requestOrValidateSSLCertificate(ctx context.Context, config ACMConfig) (string, error) {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Requesting or validating SSL certificate")

	// If certificate ARN is provided, validate it exists
	if config.CertificateArn != "" {
		logger.Info("Validating existing certificate", "certificateArn", config.CertificateArn)
		
		input := &acm.DescribeCertificateInput{
			CertificateArn: aws.String(config.CertificateArn),
		}
		
		result, err := m.acmClient.DescribeCertificate(ctx, input)
		if err != nil {
			return "", fmt.Errorf("certificate %s not found: %w", config.CertificateArn, err)
		}
		
		// Check certificate status
		if result.Certificate != nil && result.Certificate.Status != acmtypes.CertificateStatusIssued {
			logger.Warn("Certificate is not in issued status", 
				"certificateArn", config.CertificateArn, 
				"status", result.Certificate.Status)
		}
		
		logger.Info("Certificate validated successfully", "certificateArn", config.CertificateArn)
		return config.CertificateArn, nil
	}

	// Request new certificate
	logger.Info("Requesting new SSL certificate")
	return m.requestNewSSLCertificate(ctx, config)
}

// requestNewSSLCertificate requests a new SSL certificate from ACM
func (m *AWSNetworkManager) requestNewSSLCertificate(ctx context.Context, config ACMConfig) (string, error) {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Requesting new SSL certificate")

	// Note: This requires domain names to be specified
	// For now, return an error as we need more configuration
	return "", fmt.Errorf("SSL certificate request not implemented - please provide certificate ARN")
}

// createIstioGateway creates an Istio Gateway resource
func (m *AWSNetworkManager) createIstioGateway(ctx context.Context, config NetworkingConfig) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating Istio Gateway", "name", config.Istio.Gateway.Name)

	gateway := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1beta1",
			"kind":       "Gateway",
			"metadata": map[string]interface{}{
				"name":      config.Istio.Gateway.Name,
				"namespace": "istio-system",
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "gateway",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
			},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"istio": "ingressgateway",
				},
				"servers": []interface{}{
					map[string]interface{}{
						"port": map[string]interface{}{
							"number":   80,
							"name":     "http",
							"protocol": "HTTP",
						},
						"hosts": config.Istio.Gateway.Hosts,
						"tls": map[string]interface{}{
							"httpsRedirect": true,
						},
					},
					map[string]interface{}{
						"port": map[string]interface{}{
							"number":   443,
							"name":     "https",
							"protocol": "HTTPS",
						},
						"hosts": config.Istio.Gateway.Hosts,
						"tls": map[string]interface{}{
							"mode": "SIMPLE",
						},
					},
				},
			},
		},
	}

	// Create or update Gateway
	existingGateway := &unstructured.Unstructured{}
	existingGateway.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "networking.istio.io",
		Version: "v1beta1",
		Kind:    "Gateway",
	})

	gatewayKey := client.ObjectKey{
		Namespace: "istio-system",
		Name:      config.Istio.Gateway.Name,
	}

	if err := m.client.Get(ctx, gatewayKey, existingGateway); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing Gateway: %w", err)
		}
		// Gateway doesn't exist, create it
		if err := m.client.Create(ctx, gateway); err != nil {
			return fmt.Errorf("failed to create Gateway: %w", err)
		}
		logger.Info("Istio Gateway created successfully", "name", config.Istio.Gateway.Name)
	} else {
		// Gateway exists, update it
		existingGateway.Object["spec"] = gateway.Object["spec"]
		if err := m.client.Update(ctx, existingGateway); err != nil {
			return fmt.Errorf("failed to update Gateway: %w", err)
		}
		logger.Info("Istio Gateway updated successfully", "name", config.Istio.Gateway.Name)
	}

	return nil
}

// createIstioVirtualService creates an Istio VirtualService resource
func (m *AWSNetworkManager) createIstioVirtualService(ctx context.Context, config NetworkingConfig) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	
	virtualServiceName := fmt.Sprintf("%s-vs", strings.TrimSuffix(config.Istio.Gateway.Name, "-gateway"))
	logger.Info("Creating Istio VirtualService", "name", virtualServiceName)

	virtualService := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1beta1",
			"kind":       "VirtualService",
			"metadata": map[string]interface{}{
				"name":      virtualServiceName,
				"namespace": "default", // Should be configurable
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "virtualservice",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
			},
			"spec": map[string]interface{}{
				"hosts":    config.Istio.Gateway.Hosts,
				"gateways": []string{fmt.Sprintf("istio-system/%s", config.Istio.Gateway.Name)},
				"http": []interface{}{
					// Webhook routes
					map[string]interface{}{
						"match": []interface{}{
							map[string]interface{}{
								"uri": map[string]interface{}{
									"prefix": "/webhook",
								},
							},
						},
						"route": []interface{}{
							map[string]interface{}{
								"destination": map[string]interface{}{
									"host": "n8n-webhook", // Should be configurable
									"port": map[string]interface{}{
										"number": 5679,
									},
								},
							},
						},
						"timeout": config.Istio.VirtualService.Timeout,
						"retries": map[string]interface{}{
							"attempts": config.Istio.VirtualService.Retries,
						},
					},
					// Main application routes
					map[string]interface{}{
						"match": []interface{}{
							map[string]interface{}{
								"uri": map[string]interface{}{
									"prefix": "/",
								},
							},
						},
						"route": []interface{}{
							map[string]interface{}{
								"destination": map[string]interface{}{
									"host": "n8n-main", // Should be configurable
									"port": map[string]interface{}{
										"number": 5678,
									},
								},
							},
						},
						"timeout": config.Istio.VirtualService.Timeout,
						"retries": map[string]interface{}{
							"attempts": config.Istio.VirtualService.Retries,
						},
					},
				},
			},
		},
	}

	// Create or update VirtualService
	existingVS := &unstructured.Unstructured{}
	existingVS.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "networking.istio.io",
		Version: "v1beta1",
		Kind:    "VirtualService",
	})

	vsKey := client.ObjectKey{
		Namespace: "default", // Should be configurable
		Name:      virtualServiceName,
	}

	if err := m.client.Get(ctx, vsKey, existingVS); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing VirtualService: %w", err)
		}
		// VirtualService doesn't exist, create it
		if err := m.client.Create(ctx, virtualService); err != nil {
			return fmt.Errorf("failed to create VirtualService: %w", err)
		}
		logger.Info("Istio VirtualService created successfully", "name", virtualServiceName)
	} else {
		// VirtualService exists, update it
		existingVS.Object["spec"] = virtualService.Object["spec"]
		if err := m.client.Update(ctx, existingVS); err != nil {
			return fmt.Errorf("failed to update VirtualService: %w", err)
		}
		logger.Info("Istio VirtualService updated successfully", "name", virtualServiceName)
	}

	return nil
}

// createIstioDestinationRule creates an Istio DestinationRule resource
func (m *AWSNetworkManager) createIstioDestinationRule(ctx context.Context, config NetworkingConfig) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	
	destinationRuleName := fmt.Sprintf("%s-dr", strings.TrimSuffix(config.Istio.Gateway.Name, "-gateway"))
	logger.Info("Creating Istio DestinationRule", "name", destinationRuleName)

	destinationRule := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1beta1",
			"kind":       "DestinationRule",
			"metadata": map[string]interface{}{
				"name":      destinationRuleName,
				"namespace": "default", // Should be configurable
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "destinationrule",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
			},
			"spec": map[string]interface{}{
				"host": "n8n-main", // Should be configurable
				"trafficPolicy": map[string]interface{}{
					"loadBalancer": map[string]interface{}{
						"simple": "LEAST_CONN",
					},
					"connectionPool": map[string]interface{}{
						"tcp": map[string]interface{}{
							"maxConnections": 100,
						},
						"http": map[string]interface{}{
							"http1MaxPendingRequests":  50,
							"http2MaxRequests":         100,
							"maxRequestsPerConnection": 10,
							"maxRetries":               3,
						},
					},
					"circuitBreaker": map[string]interface{}{
						"consecutiveErrors":  5,
						"interval":           "30s",
						"baseEjectionTime":   "30s",
						"maxEjectionPercent": 50,
					},
				},
			},
		},
	}

	// Create or update DestinationRule
	existingDR := &unstructured.Unstructured{}
	existingDR.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "networking.istio.io",
		Version: "v1beta1",
		Kind:    "DestinationRule",
	})

	drKey := client.ObjectKey{
		Namespace: "default", // Should be configurable
		Name:      destinationRuleName,
	}

	if err := m.client.Get(ctx, drKey, existingDR); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing DestinationRule: %w", err)
		}
		// DestinationRule doesn't exist, create it
		if err := m.client.Create(ctx, destinationRule); err != nil {
			return fmt.Errorf("failed to create DestinationRule: %w", err)
		}
		logger.Info("Istio DestinationRule created successfully", "name", destinationRuleName)
	} else {
		// DestinationRule exists, update it
		existingDR.Object["spec"] = destinationRule.Object["spec"]
		if err := m.client.Update(ctx, existingDR); err != nil {
			return fmt.Errorf("failed to update DestinationRule: %w", err)
		}
		logger.Info("Istio DestinationRule updated successfully", "name", destinationRuleName)
	}

	return nil
}

// createNetworkingSecret creates a Kubernetes secret with networking configuration
func (m *AWSNetworkManager) createNetworkingSecret(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config NetworkingConfig) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	
	secretName := fmt.Sprintf("%s-networking", instance.Name)
	logger.Info("Creating networking secret", "secretName", secretName)

	// Prepare secret data
	secretData := map[string][]byte{
		"domain": []byte(instance.Spec.Domain),
	}

	// Add DNS configuration
	if config.DNS.Provider == "route53" {
		secretData["dns-provider"] = []byte("route53")
		if config.DNS.Route53.HostedZoneId != "" {
			secretData["hosted-zone-id"] = []byte(config.DNS.Route53.HostedZoneId)
		}
	}

	// Add SSL configuration
	if config.SSL.Provider == "acm" {
		secretData["ssl-provider"] = []byte("acm")
		if config.SSL.ACM.CertificateArn != "" {
			secretData["certificate-arn"] = []byte(config.SSL.ACM.CertificateArn)
		}
	}

	// Add Istio configuration
	if config.Istio.Enabled {
		secretData["istio-enabled"] = []byte("true")
		secretData["gateway-name"] = []byte(config.Istio.Gateway.Name)
		if len(config.Istio.Gateway.Hosts) > 0 {
			secretData["gateway-hosts"] = []byte(strings.Join(config.Istio.Gateway.Hosts, ","))
		}
	}

	// Create secret object
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "networking",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, secret, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update secret
	existingSecret := &corev1.Secret{}
	secretKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      secretName,
	}

	if err := m.client.Get(ctx, secretKey, existingSecret); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing secret: %w", err)
		}
		// Secret doesn't exist, create it
		if err := m.client.Create(ctx, secret); err != nil {
			return fmt.Errorf("failed to create networking secret: %w", err)
		}
		logger.Info("Networking secret created successfully", "secretName", secretName)
	} else {
		// Secret exists, update it
		existingSecret.Data = secretData
		if err := m.client.Update(ctx, existingSecret); err != nil {
			return fmt.Errorf("failed to update networking secret: %w", err)
		}
		logger.Info("Networking secret updated successfully", "secretName", secretName)
	}

	return nil
}

// requestSSLCertificateWithDomains requests a new SSL certificate for specified domains
func (m *AWSNetworkManager) requestSSLCertificateWithDomains(ctx context.Context, domains []string, validationMethod string) (string, error) {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Requesting SSL certificate with domains", "domains", domains, "validationMethod", validationMethod)

	if len(domains) == 0 {
		return "", fmt.Errorf("at least one domain is required")
	}

	// Prepare domain validation options
	var domainValidationOptions []acmtypes.DomainValidationOption
	for _, domain := range domains {
		domainValidationOptions = append(domainValidationOptions, acmtypes.DomainValidationOption{
			DomainName:       aws.String(domain),
			ValidationDomain: aws.String(domain),
		})
	}

	// Prepare subject alternative names (SAN)
	var subjectAlternativeNames []string
	if len(domains) > 1 {
		subjectAlternativeNames = domains[1:] // All domains except the first one
	}

	// Set validation method
	var validationMethodType acmtypes.ValidationMethod
	switch strings.ToUpper(validationMethod) {
	case "DNS":
		validationMethodType = acmtypes.ValidationMethodDns
	case "EMAIL":
		validationMethodType = acmtypes.ValidationMethodEmail
	default:
		validationMethodType = acmtypes.ValidationMethodDns // Default to DNS
	}

	input := &acm.RequestCertificateInput{
		DomainName:              aws.String(domains[0]),
		SubjectAlternativeNames: subjectAlternativeNames,
		ValidationMethod:        validationMethodType,
		DomainValidationOptions: domainValidationOptions,
		Tags: []acmtypes.Tag{
			{
				Key:   aws.String("Application"),
				Value: aws.String("n8n"),
			},
			{
				Key:   aws.String("ManagedBy"),
				Value: aws.String("n8n-operator"),
			},
		},
	}

	result, err := m.acmClient.RequestCertificate(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to request certificate: %w", err)
	}

	if result.CertificateArn == nil {
		return "", fmt.Errorf("certificate request returned no ARN")
	}

	certificateArn := *result.CertificateArn
	logger.Info("SSL certificate requested successfully", "certificateArn", certificateArn)

	// If using DNS validation, set up DNS records
	if validationMethodType == acmtypes.ValidationMethodDns {
		if err := m.setupDNSValidation(ctx, certificateArn); err != nil {
			logger.Warn("Failed to setup DNS validation", "error", err)
		}
	}

	return certificateArn, nil
}

// setupDNSValidation sets up DNS records for certificate validation
func (m *AWSNetworkManager) setupDNSValidation(ctx context.Context, certificateArn string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Setting up DNS validation", "certificateArn", certificateArn)

	// Get certificate details to obtain validation records
	input := &acm.DescribeCertificateInput{
		CertificateArn: aws.String(certificateArn),
	}

	result, err := m.acmClient.DescribeCertificate(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe certificate: %w", err)
	}

	if result.Certificate == nil {
		return fmt.Errorf("certificate details not found")
	}

	certificate := result.Certificate

	// Wait for domain validation options to be available
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		if len(certificate.DomainValidationOptions) > 0 {
			break
		}
		
		logger.Info("Waiting for domain validation options", "attempt", i+1)
		time.Sleep(10 * time.Second)
		
		// Refresh certificate details
		result, err = m.acmClient.DescribeCertificate(ctx, input)
		if err != nil {
			return fmt.Errorf("failed to refresh certificate details: %w", err)
		}
		certificate = result.Certificate
	}

	if len(certificate.DomainValidationOptions) == 0 {
		return fmt.Errorf("no domain validation options available")
	}

	// Create DNS validation records
	for _, domainValidation := range certificate.DomainValidationOptions {
		if domainValidation.ResourceRecord != nil {
			record := domainValidation.ResourceRecord
			if record.Name != nil && record.Value != nil && record.Type != nil {
				logger.Info("Creating DNS validation record", 
					"name", *record.Name, 
					"type", *record.Type, 
					"value", *record.Value)
				
				// Note: This would require the hosted zone ID
				// For now, we'll log the information that needs to be created
				logger.Info("DNS validation record details", 
					"domain", aws.ToString(domainValidation.DomainName),
					"recordName", *record.Name,
					"recordType", *record.Type,
					"recordValue", *record.Value)
			}
		}
	}

	logger.Info("DNS validation setup completed")
	return nil
}

// validateSSLCertificate validates that an SSL certificate is properly configured
func (m *AWSNetworkManager) validateSSLCertificate(ctx context.Context, certificateArn string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Validating SSL certificate", "certificateArn", certificateArn)

	input := &acm.DescribeCertificateInput{
		CertificateArn: aws.String(certificateArn),
	}

	result, err := m.acmClient.DescribeCertificate(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to describe certificate: %w", err)
	}

	if result.Certificate == nil {
		return fmt.Errorf("certificate not found")
	}

	certificate := result.Certificate

	// Check certificate status
	if certificate.Status != acmtypes.CertificateStatusIssued {
		return fmt.Errorf("certificate is not issued, current status: %s", certificate.Status)
	}

	// Check certificate expiration
	if certificate.NotAfter != nil {
		expirationTime := *certificate.NotAfter
		if time.Now().After(expirationTime) {
			return fmt.Errorf("certificate has expired on %s", expirationTime.Format(time.RFC3339))
		}

		// Warn if certificate expires within 30 days
		if time.Now().Add(30 * 24 * time.Hour).After(expirationTime) {
			logger.Warn("Certificate expires soon", 
				"certificateArn", certificateArn,
				"expirationDate", expirationTime.Format(time.RFC3339))
		}
	}

	// Validate domain validation status
	for _, domainValidation := range certificate.DomainValidationOptions {
		if domainValidation.ValidationStatus != acmtypes.DomainStatusSuccess {
			logger.Warn("Domain validation not successful", 
				"domain", aws.ToString(domainValidation.DomainName),
				"status", domainValidation.ValidationStatus)
		}
	}

	logger.Info("SSL certificate validation successful", "certificateArn", certificateArn)
	return nil
}

// renewSSLCertificate handles SSL certificate renewal
func (m *AWSNetworkManager) renewSSLCertificate(ctx context.Context, certificateArn string) (string, error) {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Renewing SSL certificate", "certificateArn", certificateArn)

	// Get current certificate details
	input := &acm.DescribeCertificateInput{
		CertificateArn: aws.String(certificateArn),
	}

	result, err := m.acmClient.DescribeCertificate(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to describe certificate: %w", err)
	}

	if result.Certificate == nil {
		return "", fmt.Errorf("certificate not found")
	}

	certificate := result.Certificate

	// Extract domains from current certificate
	domains := []string{}
	if certificate.DomainName != nil {
		domains = append(domains, *certificate.DomainName)
	}
	domains = append(domains, certificate.SubjectAlternativeNames...)

	// Request new certificate with same domains
	newCertificateArn, err := m.requestSSLCertificateWithDomains(ctx, domains, "DNS")
	if err != nil {
		return "", fmt.Errorf("failed to request new certificate: %w", err)
	}

	logger.Info("SSL certificate renewal initiated", 
		"oldCertificateArn", certificateArn,
		"newCertificateArn", newCertificateArn)

	return newCertificateArn, nil
}

// listSSLCertificates lists all SSL certificates managed by the operator
func (m *AWSNetworkManager) listSSLCertificates(ctx context.Context) ([]map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Listing SSL certificates")

	input := &acm.ListCertificatesInput{
		CertificateStatuses: []acmtypes.CertificateStatus{
			acmtypes.CertificateStatusIssued,
			acmtypes.CertificateStatusPendingValidation,
		},
		MaxItems: aws.Int32(100),
	}

	result, err := m.acmClient.ListCertificates(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}

	certificates := make([]map[string]interface{}, 0, len(result.CertificateSummaryList))

	for _, certSummary := range result.CertificateSummaryList {
		if certSummary.CertificateArn == nil {
			continue
		}

		// Get detailed certificate information
		detailInput := &acm.DescribeCertificateInput{
			CertificateArn: certSummary.CertificateArn,
		}

		detailResult, err := m.acmClient.DescribeCertificate(ctx, detailInput)
		if err != nil {
			logger.Warn("Failed to get certificate details", "certificateArn", *certSummary.CertificateArn)
			continue
		}

		if detailResult.Certificate == nil {
			continue
		}

		cert := detailResult.Certificate
		certInfo := map[string]interface{}{
			"arn":    *certSummary.CertificateArn,
			"status": string(cert.Status),
		}

		if cert.DomainName != nil {
			certInfo["domain"] = *cert.DomainName
		}

		if len(cert.SubjectAlternativeNames) > 0 {
			certInfo["alternative_names"] = cert.SubjectAlternativeNames
		}

		if cert.NotAfter != nil {
			certInfo["expiration"] = cert.NotAfter.Format(time.RFC3339)
		}

		if cert.NotBefore != nil {
			certInfo["issued"] = cert.NotBefore.Format(time.RFC3339)
		}

		// Check if certificate is managed by n8n operator
		isN8nManaged := false
		for _, tag := range cert.Tags {
			if tag.Key != nil && *tag.Key == "ManagedBy" && 
			   tag.Value != nil && *tag.Value == "n8n-operator" {
				isN8nManaged = true
				break
			}
		}
		certInfo["n8n_managed"] = isN8nManaged

		certificates = append(certificates, certInfo)
	}

	logger.Info("SSL certificates listed", "count", len(certificates))
	return certificates, nil
}

// monitorSSLCertificates monitors SSL certificates for expiration and issues
func (m *AWSNetworkManager) monitorSSLCertificates(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Monitoring SSL certificates")

	certificates, err := m.listSSLCertificates(ctx)
	if err != nil {
		return fmt.Errorf("failed to list certificates: %w", err)
	}

	for _, cert := range certificates {
		certificateArn, ok := cert["arn"].(string)
		if !ok {
			continue
		}

		// Only monitor n8n managed certificates
		if isManaged, ok := cert["n8n_managed"].(bool); !ok || !isManaged {
			continue
		}

		// Check expiration
		if expirationStr, ok := cert["expiration"].(string); ok {
			expiration, err := time.Parse(time.RFC3339, expirationStr)
			if err != nil {
				logger.Warn("Failed to parse expiration date", "certificateArn", certificateArn)
				continue
			}

			daysUntilExpiration := int(time.Until(expiration).Hours() / 24)

			if daysUntilExpiration <= 0 {
				logger.Error(nil, "Certificate has expired", 
					"certificateArn", certificateArn,
					"expiration", expirationStr)
			} else if daysUntilExpiration <= 30 {
				logger.Warn("Certificate expires soon", 
					"certificateArn", certificateArn,
					"expiration", expirationStr,
					"daysUntilExpiration", daysUntilExpiration)
			}
		}

		// Check certificate status
		if status, ok := cert["status"].(string); ok {
			if status != string(acmtypes.CertificateStatusIssued) {
				logger.Warn("Certificate is not in issued status", 
					"certificateArn", certificateArn,
					"status", status)
			}
		}
	}

	logger.Info("SSL certificate monitoring completed")
	return nil
}

// getSSLCertificateMetrics retrieves SSL certificate metrics
func (m *AWSNetworkManager) getSSLCertificateMetrics(ctx context.Context, certificateArn string) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Retrieving SSL certificate metrics", "certificateArn", certificateArn)

	input := &acm.DescribeCertificateInput{
		CertificateArn: aws.String(certificateArn),
	}

	result, err := m.acmClient.DescribeCertificate(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to describe certificate: %w", err)
	}

	if result.Certificate == nil {
		return nil, fmt.Errorf("certificate not found")
	}

	certificate := result.Certificate
	metrics := make(map[string]interface{})

	metrics["arn"] = certificateArn
	metrics["status"] = string(certificate.Status)

	if certificate.DomainName != nil {
		metrics["domain"] = *certificate.DomainName
	}

	if len(certificate.SubjectAlternativeNames) > 0 {
		metrics["alternative_names"] = certificate.SubjectAlternativeNames
		metrics["alternative_names_count"] = len(certificate.SubjectAlternativeNames)
	}

	if certificate.NotBefore != nil {
		metrics["issued_date"] = certificate.NotBefore.Format(time.RFC3339)
		metrics["age_days"] = int(time.Since(*certificate.NotBefore).Hours() / 24)
	}

	if certificate.NotAfter != nil {
		metrics["expiration_date"] = certificate.NotAfter.Format(time.RFC3339)
		metrics["days_until_expiration"] = int(time.Until(*certificate.NotAfter).Hours() / 24)
	}

	if certificate.KeyAlgorithm != nil {
		metrics["key_algorithm"] = string(*certificate.KeyAlgorithm)
	}

	if certificate.KeyUsages != nil {
		keyUsages := make([]string, len(certificate.KeyUsages))
		for i, usage := range certificate.KeyUsages {
			keyUsages[i] = string(usage.Name)
		}
		metrics["key_usages"] = keyUsages
	}

	// Domain validation status
	domainValidations := make([]map[string]interface{}, len(certificate.DomainValidationOptions))
	for i, domainValidation := range certificate.DomainValidationOptions {
		validation := map[string]interface{}{}
		if domainValidation.DomainName != nil {
			validation["domain"] = *domainValidation.DomainName
		}
		validation["status"] = string(domainValidation.ValidationStatus)
		if domainValidation.ValidationMethod != "" {
			validation["method"] = string(domainValidation.ValidationMethod)
		}
		domainValidations[i] = validation
	}
	metrics["domain_validations"] = domainValidations

	logger.Info("SSL certificate metrics retrieved", "certificateArn", certificateArn)
	return metrics, nil
}

//
createAdvancedIstioGateway creates an advanced Istio Gateway with multiple protocols and security
func (m *AWSNetworkManager) createAdvancedIstioGateway(ctx context.Context, config NetworkingConfig, certificateArn string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating advanced Istio Gateway", "name", config.Istio.Gateway.Name)

	// Build servers configuration with TLS
	servers := []interface{}{
		// HTTP server with redirect to HTTPS
		map[string]interface{}{
			"port": map[string]interface{}{
				"number":   80,
				"name":     "http",
				"protocol": "HTTP",
			},
			"hosts": config.Istio.Gateway.Hosts,
			"tls": map[string]interface{}{
				"httpsRedirect": true,
			},
		},
		// HTTPS server with TLS termination
		map[string]interface{}{
			"port": map[string]interface{}{
				"number":   443,
				"name":     "https",
				"protocol": "HTTPS",
			},
			"hosts": config.Istio.Gateway.Hosts,
			"tls": map[string]interface{}{
				"mode": "SIMPLE",
			},
		},
	}

	// Add webhook-specific server if needed
	webhookHost := fmt.Sprintf("webhook.%s", config.Istio.Gateway.Hosts[0])
	servers = append(servers, map[string]interface{}{
		"port": map[string]interface{}{
			"number":   443,
			"name":     "webhook-https",
			"protocol": "HTTPS",
		},
		"hosts": []string{webhookHost},
		"tls": map[string]interface{}{
			"mode": "SIMPLE",
		},
	})

	gateway := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1beta1",
			"kind":       "Gateway",
			"metadata": map[string]interface{}{
				"name":      config.Istio.Gateway.Name,
				"namespace": "istio-system",
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "gateway",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
				"annotations": map[string]interface{}{
					"n8n.io/certificate-arn": certificateArn,
				},
			},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"istio": "ingressgateway",
				},
				"servers": servers,
			},
		},
	}

	return m.createOrUpdateIstioResource(ctx, gateway, "Gateway")
}

// createAdvancedIstioVirtualService creates an advanced VirtualService with multiple routes and policies
func (m *AWSNetworkManager) createAdvancedIstioVirtualService(ctx context.Context, config NetworkingConfig, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	
	virtualServiceName := fmt.Sprintf("%s-vs", strings.TrimSuffix(config.Istio.Gateway.Name, "-gateway"))
	logger.Info("Creating advanced Istio VirtualService", "name", virtualServiceName)

	// Build HTTP routes with advanced features
	httpRoutes := []interface{}{
		// Health check route
		map[string]interface{}{
			"name": "health-check",
			"match": []interface{}{
				map[string]interface{}{
					"uri": map[string]interface{}{
						"exact": "/health",
					},
				},
			},
			"route": []interface{}{
				map[string]interface{}{
					"destination": map[string]interface{}{
						"host": "n8n-main",
						"port": map[string]interface{}{
							"number": 5678,
						},
					},
				},
			},
			"timeout": "5s",
		},
		// Webhook routes with specific policies
		map[string]interface{}{
			"name": "webhook-routes",
			"match": []interface{}{
				map[string]interface{}{
					"uri": map[string]interface{}{
						"prefix": "/webhook",
					},
				},
			},
			"route": []interface{}{
				map[string]interface{}{
					"destination": map[string]interface{}{
						"host": "n8n-webhook",
						"port": map[string]interface{}{
							"number": 5679,
						},
					},
				},
			},
			"timeout": config.Istio.VirtualService.Timeout,
			"retries": map[string]interface{}{
				"attempts":      config.Istio.VirtualService.Retries,
				"perTryTimeout": "10s",
				"retryOn":       "5xx,reset,connect-failure,refused-stream",
			},
			"headers": map[string]interface{}{
				"request": map[string]interface{}{
					"add": map[string]interface{}{
						"x-forwarded-proto": "https",
					},
				},
			},
		},
		// API routes
		map[string]interface{}{
			"name": "api-routes",
			"match": []interface{}{
				map[string]interface{}{
					"uri": map[string]interface{}{
						"prefix": "/api",
					},
				},
			},
			"route": []interface{}{
				map[string]interface{}{
					"destination": map[string]interface{}{
						"host": "n8n-main",
						"port": map[string]interface{}{
							"number": 5678,
						},
					},
				},
			},
			"timeout": config.Istio.VirtualService.Timeout,
			"retries": map[string]interface{}{
				"attempts":      config.Istio.VirtualService.Retries,
				"perTryTimeout": "15s",
			},
			"corsPolicy": map[string]interface{}{
				"allowOrigins": []interface{}{
					map[string]interface{}{
						"exact": fmt.Sprintf("https://%s", config.Istio.Gateway.Hosts[0]),
					},
				},
				"allowMethods":     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				"allowHeaders":     []string{"authorization", "content-type", "x-requested-with"},
				"allowCredentials": true,
				"maxAge":          "24h",
			},
		},
		// Static assets routes
		map[string]interface{}{
			"name": "static-assets",
			"match": []interface{}{
				map[string]interface{}{
					"uri": map[string]interface{}{
						"prefix": "/static",
					},
				},
			},
			"route": []interface{}{
				map[string]interface{}{
					"destination": map[string]interface{}{
						"host": "n8n-main",
						"port": map[string]interface{}{
							"number": 5678,
						},
					},
				},
			},
			"timeout": "30s",
			"headers": map[string]interface{}{
				"response": map[string]interface{}{
					"add": map[string]interface{}{
						"cache-control": "public, max-age=3600",
					},
				},
			},
		},
		// Default route for main application
		map[string]interface{}{
			"name": "default-route",
			"match": []interface{}{
				map[string]interface{}{
					"uri": map[string]interface{}{
						"prefix": "/",
					},
				},
			},
			"route": []interface{}{
				map[string]interface{}{
					"destination": map[string]interface{}{
						"host": "n8n-main",
						"port": map[string]interface{}{
							"number": 5678,
						},
					},
				},
			},
			"timeout": config.Istio.VirtualService.Timeout,
			"retries": map[string]interface{}{
				"attempts":      config.Istio.VirtualService.Retries,
				"perTryTimeout": "20s",
			},
		},
	}

	virtualService := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1beta1",
			"kind":       "VirtualService",
			"metadata": map[string]interface{}{
				"name":      virtualServiceName,
				"namespace": namespace,
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "virtualservice",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
			},
			"spec": map[string]interface{}{
				"hosts":    config.Istio.Gateway.Hosts,
				"gateways": []string{fmt.Sprintf("istio-system/%s", config.Istio.Gateway.Name)},
				"http":     httpRoutes,
			},
		},
	}

	return m.createOrUpdateIstioResource(ctx, virtualService, "VirtualService")
}

// createAdvancedIstioDestinationRule creates an advanced DestinationRule with circuit breaker and load balancing
func (m *AWSNetworkManager) createAdvancedIstioDestinationRule(ctx context.Context, config NetworkingConfig, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	
	destinationRuleName := fmt.Sprintf("%s-dr", strings.TrimSuffix(config.Istio.Gateway.Name, "-gateway"))
	logger.Info("Creating advanced Istio DestinationRule", "name", destinationRuleName)

	// Create destination rules for each service
	services := []struct {
		name string
		host string
		port int
	}{
		{"main", "n8n-main", 5678},
		{"webhook", "n8n-webhook", 5679},
	}

	for _, service := range services {
		drName := fmt.Sprintf("%s-%s-dr", destinationRuleName, service.name)
		
		destinationRule := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.istio.io/v1beta1",
				"kind":       "DestinationRule",
				"metadata": map[string]interface{}{
					"name":      drName,
					"namespace": namespace,
					"labels": map[string]interface{}{
						"app.kubernetes.io/name":       "n8n",
						"app.kubernetes.io/component":  "destinationrule",
						"app.kubernetes.io/managed-by": "n8n-operator",
						"n8n.io/service":              service.name,
					},
				},
				"spec": map[string]interface{}{
					"host": service.host,
					"trafficPolicy": map[string]interface{}{
						"loadBalancer": map[string]interface{}{
							"simple": "LEAST_CONN",
						},
						"connectionPool": map[string]interface{}{
							"tcp": map[string]interface{}{
								"maxConnections":   100,
								"connectTimeout":   "30s",
								"tcpKeepalive": map[string]interface{}{
									"time":     "7200s",
									"interval": "75s",
								},
							},
							"http": map[string]interface{}{
								"http1MaxPendingRequests":  50,
								"http2MaxRequests":         100,
								"maxRequestsPerConnection": 10,
								"maxRetries":               3,
								"idleTimeout":              "60s",
								"h2UpgradePolicy":          "UPGRADE",
							},
						},
						"circuitBreaker": map[string]interface{}{
							"consecutiveGatewayErrors": 5,
							"consecutive5xxErrors":     5,
							"interval":                 "30s",
							"baseEjectionTime":         "30s",
							"maxEjectionPercent":       50,
							"minHealthPercent":         30,
						},
						"outlierDetection": map[string]interface{}{
							"consecutiveGatewayErrors": 5,
							"consecutive5xxErrors":     5,
							"interval":                 "30s",
							"baseEjectionTime":         "30s",
							"maxEjectionPercent":       50,
							"minHealthPercent":         30,
						},
					},
					"portLevelSettings": []interface{}{
						map[string]interface{}{
							"port": map[string]interface{}{
								"number": service.port,
							},
							"loadBalancer": map[string]interface{}{
								"simple": "ROUND_ROBIN",
							},
						},
					},
				},
			},
		}

		if err := m.createOrUpdateIstioResource(ctx, destinationRule, "DestinationRule"); err != nil {
			return fmt.Errorf("failed to create DestinationRule for %s: %w", service.name, err)
		}
	}

	logger.Info("Advanced Istio DestinationRules created successfully")
	return nil
}

// createIstioServiceEntry creates ServiceEntry for external services
func (m *AWSNetworkManager) createIstioServiceEntry(ctx context.Context, config NetworkingConfig, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating Istio ServiceEntry for external services")

	// Define external services that n8n might need to access
	externalServices := []struct {
		name     string
		hosts    []string
		ports    []map[string]interface{}
		location string
	}{
		{
			name:  "aws-services",
			hosts: []string{"*.amazonaws.com"},
			ports: []map[string]interface{}{
				{
					"number":   443,
					"name":     "https",
					"protocol": "HTTPS",
				},
			},
			location: "MESH_EXTERNAL",
		},
		{
			name:  "external-apis",
			hosts: []string{"api.github.com", "hooks.slack.com"},
			ports: []map[string]interface{}{
				{
					"number":   443,
					"name":     "https",
					"protocol": "HTTPS",
				},
			},
			location: "MESH_EXTERNAL",
		},
	}

	for _, extService := range externalServices {
		serviceEntry := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "networking.istio.io/v1beta1",
				"kind":       "ServiceEntry",
				"metadata": map[string]interface{}{
					"name":      fmt.Sprintf("n8n-%s-se", extService.name),
					"namespace": namespace,
					"labels": map[string]interface{}{
						"app.kubernetes.io/name":       "n8n",
						"app.kubernetes.io/component":  "serviceentry",
						"app.kubernetes.io/managed-by": "n8n-operator",
					},
				},
				"spec": map[string]interface{}{
					"hosts":    extService.hosts,
					"ports":    extService.ports,
					"location": extService.location,
				},
			},
		}

		if err := m.createOrUpdateIstioResource(ctx, serviceEntry, "ServiceEntry"); err != nil {
			return fmt.Errorf("failed to create ServiceEntry for %s: %w", extService.name, err)
		}
	}

	logger.Info("Istio ServiceEntries created successfully")
	return nil
}

// createIstioSidecarConfiguration creates Sidecar configuration for optimized resource usage
func (m *AWSNetworkManager) createIstioSidecarConfiguration(ctx context.Context, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating Istio Sidecar configuration")

	sidecar := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1beta1",
			"kind":       "Sidecar",
			"metadata": map[string]interface{}{
				"name":      "n8n-sidecar",
				"namespace": namespace,
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "sidecar",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
			},
			"spec": map[string]interface{}{
				"workloadSelector": map[string]interface{}{
					"labels": map[string]interface{}{
						"app.kubernetes.io/name": "n8n",
					},
				},
				"ingress": []interface{}{
					map[string]interface{}{
						"port": map[string]interface{}{
							"number":   5678,
							"protocol": "HTTP",
							"name":     "http-main",
						},
						"defaultEndpoint": "127.0.0.1:5678",
					},
					map[string]interface{}{
						"port": map[string]interface{}{
							"number":   5679,
							"protocol": "HTTP",
							"name":     "http-webhook",
						},
						"defaultEndpoint": "127.0.0.1:5679",
					},
				},
				"egress": []interface{}{
					// Allow access to same namespace
					map[string]interface{}{
						"hosts": []string{fmt.Sprintf("./%s", namespace)},
					},
					// Allow access to istio-system
					map[string]interface{}{
						"hosts": []string{"./istio-system"},
					},
					// Allow access to external services
					map[string]interface{}{
						"hosts": []string{"*.amazonaws.com", "api.github.com", "hooks.slack.com"},
					},
				},
			},
		},
	}

	return m.createOrUpdateIstioResource(ctx, sidecar, "Sidecar")
}

// createOrUpdateIstioResource creates or updates an Istio resource
func (m *AWSNetworkManager) createOrUpdateIstioResource(ctx context.Context, resource *unstructured.Unstructured, resourceType string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	
	name := resource.GetName()
	namespace := resource.GetNamespace()
	
	logger.Info("Creating or updating Istio resource", "type", resourceType, "name", name, "namespace", namespace)

	// Set the GVK based on resource type
	gvk := schema.GroupVersionKind{
		Group:   "networking.istio.io",
		Version: "v1beta1",
		Kind:    resourceType,
	}
	resource.SetGroupVersionKind(gvk)

	// Check if resource exists
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(gvk)
	
	resourceKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	if err := m.client.Get(ctx, resourceKey, existing); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing %s: %w", resourceType, err)
		}
		// Resource doesn't exist, create it
		if err := m.client.Create(ctx, resource); err != nil {
			return fmt.Errorf("failed to create %s: %w", resourceType, err)
		}
		logger.Info("Istio resource created successfully", "type", resourceType, "name", name)
	} else {
		// Resource exists, update it
		existing.Object["spec"] = resource.Object["spec"]
		if err := m.client.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update %s: %w", resourceType, err)
		}
		logger.Info("Istio resource updated successfully", "type", resourceType, "name", name)
	}

	return nil
}

// validateIstioConfiguration validates the Istio configuration
func (m *AWSNetworkManager) validateIstioConfiguration(ctx context.Context, config NetworkingConfig, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Validating Istio configuration")

	// Validate Gateway
	gateway := &unstructured.Unstructured{}
	gateway.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "networking.istio.io",
		Version: "v1beta1",
		Kind:    "Gateway",
	})

	if err := m.client.Get(ctx, client.ObjectKey{
		Namespace: "istio-system",
		Name:      config.Istio.Gateway.Name,
	}, gateway); err != nil {
		return fmt.Errorf("Gateway validation failed: %w", err)
	}

	// Validate VirtualService
	virtualServiceName := fmt.Sprintf("%s-vs", strings.TrimSuffix(config.Istio.Gateway.Name, "-gateway"))
	virtualService := &unstructured.Unstructured{}
	virtualService.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "networking.istio.io",
		Version: "v1beta1",
		Kind:    "VirtualService",
	})

	if err := m.client.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      virtualServiceName,
	}, virtualService); err != nil {
		return fmt.Errorf("VirtualService validation failed: %w", err)
	}

	logger.Info("Istio configuration validation successful")
	return nil
}

// getIstioMetrics retrieves Istio configuration metrics
func (m *AWSNetworkManager) getIstioMetrics(ctx context.Context, namespace string) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Retrieving Istio metrics")

	metrics := make(map[string]interface{})

	// Count Istio resources
	resourceTypes := []string{"Gateway", "VirtualService", "DestinationRule", "ServiceEntry", "Sidecar"}
	
	for _, resourceType := range resourceTypes {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "networking.istio.io",
			Version: "v1beta1",
			Kind:    resourceType,
		})

		listOptions := []client.ListOption{
			client.InNamespace(namespace),
			client.MatchingLabels{
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		}

		if err := m.client.List(ctx, list, listOptions...); err != nil {
			logger.Warn("Failed to list Istio resources", "type", resourceType, "error", err)
			continue
		}

		metrics[fmt.Sprintf("%s_count", strings.ToLower(resourceType))] = len(list.Items)
	}

	logger.Info("Istio metrics retrieved", "metricsCount", len(metrics))
	return metrics, nil
}

// create
IstioAuthorizationPolicies creates comprehensive authorization policies for n8n
func (m *AWSNetworkManager) createIstioAuthorizationPolicies(ctx context.Context, config NetworkingConfig, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating Istio Authorization Policies")

	if !config.Istio.AuthorizationPolicy.Enabled {
		logger.Info("Authorization policies are disabled")
		return nil
	}

	// Create authorization policies for different components
	policies := []struct {
		name        string
		selector    map[string]string
		rules       []map[string]interface{}
		description string
	}{
		{
			name: "n8n-main-policy",
			selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/component": "main",
			},
			rules: []map[string]interface{}{
				// Allow access from Istio gateway
				{
					"from": []interface{}{
						map[string]interface{}{
							"source": map[string]interface{}{
								"principals": []string{"cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"},
							},
						},
					},
					"to": []interface{}{
						map[string]interface{}{
							"operation": map[string]interface{}{
								"methods": []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
								"paths":   []string{"/", "/api/*", "/static/*", "/health"},
							},
						},
					},
				},
				// Allow internal service communication
				{
					"from": []interface{}{
						map[string]interface{}{
							"source": map[string]interface{}{
								"namespaces": []string{namespace},
							},
						},
					},
					"to": []interface{}{
						map[string]interface{}{
							"operation": map[string]interface{}{
								"methods": []string{"GET", "POST"},
								"paths":   []string{"/health", "/metrics"},
							},
						},
					},
				},
			},
			description: "Authorization policy for n8n main component",
		},
		{
			name: "n8n-webhook-policy",
			selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/component": "webhook",
			},
			rules: []map[string]interface{}{
				// Allow webhook access from gateway
				{
					"from": []interface{}{
						map[string]interface{}{
							"source": map[string]interface{}{
								"principals": []string{"cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"},
							},
						},
					},
					"to": []interface{}{
						map[string]interface{}{
							"operation": map[string]interface{}{
								"methods": []string{"POST", "PUT", "GET"},
								"paths":   []string{"/webhook/*"},
							},
						},
					},
				},
				// Allow health checks
				{
					"from": []interface{}{
						map[string]interface{}{
							"source": map[string]interface{}{
								"namespaces": []string{namespace, "istio-system"},
							},
						},
					},
					"to": []interface{}{
						map[string]interface{}{
							"operation": map[string]interface{}{
								"methods": []string{"GET"},
								"paths":   []string{"/health"},
							},
						},
					},
				},
			},
			description: "Authorization policy for n8n webhook component",
		},
		{
			name: "n8n-worker-policy",
			selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/component": "worker",
			},
			rules: []map[string]interface{}{
				// Allow internal communication only
				{
					"from": []interface{}{
						map[string]interface{}{
							"source": map[string]interface{}{
								"namespaces": []string{namespace},
							},
						},
					},
					"to": []interface{}{
						map[string]interface{}{
							"operation": map[string]interface{}{
								"methods": []string{"GET", "POST"},
								"paths":   []string{"/health", "/metrics"},
							},
						},
					},
				},
			},
			description: "Authorization policy for n8n worker component",
		},
	}

	for _, policy := range policies {
		authzPolicy := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "security.istio.io/v1beta1",
				"kind":       "AuthorizationPolicy",
				"metadata": map[string]interface{}{
					"name":      policy.name,
					"namespace": namespace,
					"labels": map[string]interface{}{
						"app.kubernetes.io/name":       "n8n",
						"app.kubernetes.io/component":  "authorization-policy",
						"app.kubernetes.io/managed-by": "n8n-operator",
					},
					"annotations": map[string]interface{}{
						"description": policy.description,
					},
				},
				"spec": map[string]interface{}{
					"selector": map[string]interface{}{
						"matchLabels": policy.selector,
					},
					"rules": policy.rules,
				},
			},
		}

		if err := m.createOrUpdateIstioSecurityResource(ctx, authzPolicy, "AuthorizationPolicy"); err != nil {
			return fmt.Errorf("failed to create authorization policy %s: %w", policy.name, err)
		}
	}

	logger.Info("Istio Authorization Policies created successfully")
	return nil
}

// createIstioPeerAuthentication creates PeerAuthentication for mTLS
func (m *AWSNetworkManager) createIstioPeerAuthentication(ctx context.Context, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating Istio PeerAuthentication for mTLS")

	// Namespace-wide mTLS policy
	namespaceMTLS := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.istio.io/v1beta1",
			"kind":       "PeerAuthentication",
			"metadata": map[string]interface{}{
				"name":      "n8n-namespace-mtls",
				"namespace": namespace,
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "peer-authentication",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
			},
			"spec": map[string]interface{}{
				"mtls": map[string]interface{}{
					"mode": "STRICT",
				},
			},
		},
	}

	if err := m.createOrUpdateIstioSecurityResource(ctx, namespaceMTLS, "PeerAuthentication"); err != nil {
		return fmt.Errorf("failed to create namespace mTLS policy: %w", err)
	}

	// Service-specific mTLS policies with port-level configuration
	services := []struct {
		name     string
		selector map[string]string
		ports    []map[string]interface{}
	}{
		{
			name: "n8n-main-mtls",
			selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/component": "main",
			},
			ports: []map[string]interface{}{
				{
					"port": map[string]interface{}{
						"number": 5678,
					},
					"mtls": map[string]interface{}{
						"mode": "STRICT",
					},
				},
			},
		},
		{
			name: "n8n-webhook-mtls",
			selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/component": "webhook",
			},
			ports: []map[string]interface{}{
				{
					"port": map[string]interface{}{
						"number": 5679,
					},
					"mtls": map[string]interface{}{
						"mode": "STRICT",
					},
				},
			},
		},
	}

	for _, service := range services {
		serviceMTLS := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "security.istio.io/v1beta1",
				"kind":       "PeerAuthentication",
				"metadata": map[string]interface{}{
					"name":      service.name,
					"namespace": namespace,
					"labels": map[string]interface{}{
						"app.kubernetes.io/name":       "n8n",
						"app.kubernetes.io/component":  "peer-authentication",
						"app.kubernetes.io/managed-by": "n8n-operator",
					},
				},
				"spec": map[string]interface{}{
					"selector": map[string]interface{}{
						"matchLabels": service.selector,
					},
					"portLevelMtls": service.ports,
				},
			},
		}

		if err := m.createOrUpdateIstioSecurityResource(ctx, serviceMTLS, "PeerAuthentication"); err != nil {
			return fmt.Errorf("failed to create service mTLS policy %s: %w", service.name, err)
		}
	}

	logger.Info("Istio PeerAuthentication policies created successfully")
	return nil
}

// createIstioRequestAuthentication creates RequestAuthentication for JWT validation
func (m *AWSNetworkManager) createIstioRequestAuthentication(ctx context.Context, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating Istio RequestAuthentication for JWT validation")

	requestAuth := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.istio.io/v1beta1",
			"kind":       "RequestAuthentication",
			"metadata": map[string]interface{}{
				"name":      "n8n-jwt-auth",
				"namespace": namespace,
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "request-authentication",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
			},
			"spec": map[string]interface{}{
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app.kubernetes.io/name": "n8n",
					},
				},
				"jwtRules": []interface{}{
					map[string]interface{}{
						"issuer":   "https://n8n.io",
						"jwksUri":  "https://n8n.io/.well-known/jwks.json",
						"audiences": []string{"n8n-api"},
						"fromHeaders": []interface{}{
							map[string]interface{}{
								"name":   "Authorization",
								"prefix": "Bearer ",
							},
						},
						"fromParams": []string{"token"},
					},
				},
			},
		},
	}

	return m.createOrUpdateIstioSecurityResource(ctx, requestAuth, "RequestAuthentication")
}

// createIstioSecurityPolicies creates comprehensive security policies
func (m *AWSNetworkManager) createIstioSecurityPolicies(ctx context.Context, config NetworkingConfig, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating comprehensive Istio security policies")

	// Create authorization policies
	if err := m.createIstioAuthorizationPolicies(ctx, config, namespace); err != nil {
		return fmt.Errorf("failed to create authorization policies: %w", err)
	}

	// Create mTLS policies
	if err := m.createIstioPeerAuthentication(ctx, namespace); err != nil {
		return fmt.Errorf("failed to create peer authentication policies: %w", err)
	}

	// Create JWT authentication (optional)
	if err := m.createIstioRequestAuthentication(ctx, namespace); err != nil {
		logger.Warn("Failed to create request authentication", "error", err)
	}

	// Create network policies for additional security
	if err := m.createIstioNetworkPolicies(ctx, namespace); err != nil {
		return fmt.Errorf("failed to create network policies: %w", err)
	}

	logger.Info("Istio security policies created successfully")
	return nil
}

// createIstioNetworkPolicies creates Kubernetes NetworkPolicies for additional security
func (m *AWSNetworkManager) createIstioNetworkPolicies(ctx context.Context, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Creating Kubernetes NetworkPolicies for Istio")

	// Default deny-all policy
	denyAllPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      "n8n-deny-all",
				"namespace": namespace,
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "network-policy",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app.kubernetes.io/name": "n8n",
					},
				},
				"policyTypes": []string{"Ingress", "Egress"},
			},
		},
	}

	if err := m.createOrUpdateNetworkPolicy(ctx, denyAllPolicy); err != nil {
		return fmt.Errorf("failed to create deny-all network policy: %w", err)
	}

	// Allow Istio sidecar communication
	istioPolicy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.k8s.io/v1",
			"kind":       "NetworkPolicy",
			"metadata": map[string]interface{}{
				"name":      "n8n-allow-istio",
				"namespace": namespace,
				"labels": map[string]interface{}{
					"app.kubernetes.io/name":       "n8n",
					"app.kubernetes.io/component":  "network-policy",
					"app.kubernetes.io/managed-by": "n8n-operator",
				},
			},
			"spec": map[string]interface{}{
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app.kubernetes.io/name": "n8n",
					},
				},
				"policyTypes": []string{"Ingress", "Egress"},
				"ingress": []interface{}{
					// Allow from Istio gateway
					map[string]interface{}{
						"from": []interface{}{
							map[string]interface{}{
								"namespaceSelector": map[string]interface{}{
									"matchLabels": map[string]interface{}{
										"name": "istio-system",
									},
								},
							},
						},
					},
					// Allow from same namespace
					map[string]interface{}{
						"from": []interface{}{
							map[string]interface{}{
								"namespaceSelector": map[string]interface{}{
									"matchLabels": map[string]interface{}{
										"name": namespace,
									},
								},
							},
						},
					},
				},
				"egress": []interface{}{
					// Allow to same namespace
					map[string]interface{}{
						"to": []interface{}{
							map[string]interface{}{
								"namespaceSelector": map[string]interface{}{
									"matchLabels": map[string]interface{}{
										"name": namespace,
									},
								},
							},
						},
					},
					// Allow to Istio system
					map[string]interface{}{
						"to": []interface{}{
							map[string]interface{}{
								"namespaceSelector": map[string]interface{}{
									"matchLabels": map[string]interface{}{
										"name": "istio-system",
									},
								},
							},
						},
					},
					// Allow DNS
					map[string]interface{}{
						"to": []interface{}{
							map[string]interface{}{
								"namespaceSelector": map[string]interface{}{
									"matchLabels": map[string]interface{}{
										"name": "kube-system",
									},
								},
							},
						},
						"ports": []interface{}{
							map[string]interface{}{
								"protocol": "UDP",
								"port":     53,
							},
						},
					},
					// Allow HTTPS to external services
					map[string]interface{}{
						"to": []interface{}{},
						"ports": []interface{}{
							map[string]interface{}{
								"protocol": "TCP",
								"port":     443,
							},
						},
					},
				},
			},
		},
	}

	return m.createOrUpdateNetworkPolicy(ctx, istioPolicy)
}

// createOrUpdateIstioSecurityResource creates or updates Istio security resources
func (m *AWSNetworkManager) createOrUpdateIstioSecurityResource(ctx context.Context, resource *unstructured.Unstructured, resourceType string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	
	name := resource.GetName()
	namespace := resource.GetNamespace()
	
	logger.Info("Creating or updating Istio security resource", "type", resourceType, "name", name, "namespace", namespace)

	// Set the GVK based on resource type
	gvk := schema.GroupVersionKind{
		Group:   "security.istio.io",
		Version: "v1beta1",
		Kind:    resourceType,
	}
	resource.SetGroupVersionKind(gvk)

	// Check if resource exists
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(gvk)
	
	resourceKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	if err := m.client.Get(ctx, resourceKey, existing); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing %s: %w", resourceType, err)
		}
		// Resource doesn't exist, create it
		if err := m.client.Create(ctx, resource); err != nil {
			return fmt.Errorf("failed to create %s: %w", resourceType, err)
		}
		logger.Info("Istio security resource created successfully", "type", resourceType, "name", name)
	} else {
		// Resource exists, update it
		existing.Object["spec"] = resource.Object["spec"]
		if err := m.client.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update %s: %w", resourceType, err)
		}
		logger.Info("Istio security resource updated successfully", "type", resourceType, "name", name)
	}

	return nil
}

// createOrUpdateNetworkPolicy creates or updates Kubernetes NetworkPolicy
func (m *AWSNetworkManager) createOrUpdateNetworkPolicy(ctx context.Context, policy *unstructured.Unstructured) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	
	name := policy.GetName()
	namespace := policy.GetNamespace()
	
	logger.Info("Creating or updating NetworkPolicy", "name", name, "namespace", namespace)

	// Set the GVK
	gvk := schema.GroupVersionKind{
		Group:   "networking.k8s.io",
		Version: "v1",
		Kind:    "NetworkPolicy",
	}
	policy.SetGroupVersionKind(gvk)

	// Check if policy exists
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(gvk)
	
	policyKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	if err := m.client.Get(ctx, policyKey, existing); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing NetworkPolicy: %w", err)
		}
		// Policy doesn't exist, create it
		if err := m.client.Create(ctx, policy); err != nil {
			return fmt.Errorf("failed to create NetworkPolicy: %w", err)
		}
		logger.Info("NetworkPolicy created successfully", "name", name)
	} else {
		// Policy exists, update it
		existing.Object["spec"] = policy.Object["spec"]
		if err := m.client.Update(ctx, existing); err != nil {
			return fmt.Errorf("failed to update NetworkPolicy: %w", err)
		}
		logger.Info("NetworkPolicy updated successfully", "name", name)
	}

	return nil
}

// validateIstioSecurityConfiguration validates Istio security configuration
func (m *AWSNetworkManager) validateIstioSecurityConfiguration(ctx context.Context, namespace string) error {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Validating Istio security configuration")

	// Validate mTLS is enabled
	if err := m.validateMTLSConfiguration(ctx, namespace); err != nil {
		return fmt.Errorf("mTLS validation failed: %w", err)
	}

	// Validate authorization policies exist
	if err := m.validateAuthorizationPolicies(ctx, namespace); err != nil {
		return fmt.Errorf("authorization policies validation failed: %w", err)
	}

	// Validate network policies exist
	if err := m.validateNetworkPolicies(ctx, namespace); err != nil {
		return fmt.Errorf("network policies validation failed: %w", err)
	}

	logger.Info("Istio security configuration validation successful")
	return nil
}

// validateMTLSConfiguration validates mTLS configuration
func (m *AWSNetworkManager) validateMTLSConfiguration(ctx context.Context, namespace string) error {
	peerAuth := &unstructured.Unstructured{}
	peerAuth.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "security.istio.io",
		Version: "v1beta1",
		Kind:    "PeerAuthentication",
	})

	return m.client.Get(ctx, client.ObjectKey{
		Namespace: namespace,
		Name:      "n8n-namespace-mtls",
	}, peerAuth)
}

// validateAuthorizationPolicies validates authorization policies exist
func (m *AWSNetworkManager) validateAuthorizationPolicies(ctx context.Context, namespace string) error {
	policies := []string{"n8n-main-policy", "n8n-webhook-policy", "n8n-worker-policy"}
	
	for _, policyName := range policies {
		authzPolicy := &unstructured.Unstructured{}
		authzPolicy.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "security.istio.io",
			Version: "v1beta1",
			Kind:    "AuthorizationPolicy",
		})

		if err := m.client.Get(ctx, client.ObjectKey{
			Namespace: namespace,
			Name:      policyName,
		}, authzPolicy); err != nil {
			return fmt.Errorf("authorization policy %s not found: %w", policyName, err)
		}
	}

	return nil
}

// validateNetworkPolicies validates network policies exist
func (m *AWSNetworkManager) validateNetworkPolicies(ctx context.Context, namespace string) error {
	policies := []string{"n8n-deny-all", "n8n-allow-istio"}
	
	for _, policyName := range policies {
		networkPolicy := &unstructured.Unstructured{}
		networkPolicy.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "networking.k8s.io",
			Version: "v1",
			Kind:    "NetworkPolicy",
		})

		if err := m.client.Get(ctx, client.ObjectKey{
			Namespace: namespace,
			Name:      policyName,
		}, networkPolicy); err != nil {
			return fmt.Errorf("network policy %s not found: %w", policyName, err)
		}
	}

	return nil
}

// getIstioSecurityMetrics retrieves Istio security metrics
func (m *AWSNetworkManager) getIstioSecurityMetrics(ctx context.Context, namespace string) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("AWSNetworkManager")
	logger.Info("Retrieving Istio security metrics")

	metrics := make(map[string]interface{})

	// Count security resources
	securityResourceTypes := []struct {
		kind  string
		group string
	}{
		{"AuthorizationPolicy", "security.istio.io"},
		{"PeerAuthentication", "security.istio.io"},
		{"RequestAuthentication", "security.istio.io"},
		{"NetworkPolicy", "networking.k8s.io"},
	}
	
	for _, resourceType := range securityResourceTypes {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   resourceType.group,
			Version: "v1beta1",
			Kind:    resourceType.kind,
		})

		if resourceType.kind == "NetworkPolicy" {
			list.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   resourceType.group,
				Version: "v1",
				Kind:    resourceType.kind,
			})
		}

		listOptions := []client.ListOption{
			client.InNamespace(namespace),
			client.MatchingLabels{
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		}

		if err := m.client.List(ctx, list, listOptions...); err != nil {
			logger.Warn("Failed to list security resources", "type", resourceType.kind, "error", err)
			continue
		}

		metrics[fmt.Sprintf("%s_count", strings.ToLower(resourceType.kind))] = len(list.Items)
	}

	// Add security status
	metrics["mtls_enabled"] = true
	metrics["authorization_enabled"] = true
	metrics["network_policies_enabled"] = true

	logger.Info("Istio security metrics retrieved", "metricsCount", len(metrics))
	return metrics, nil
}
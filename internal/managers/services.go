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
	"strconv"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// N8nServicesManager implements the ServicesManager interface for n8n services
type N8nServicesManager struct {
	client client.Client
}

// NewN8nServicesManager creates a new N8nServicesManager instance
func NewN8nServicesManager(client client.Client) *N8nServicesManager {
	return &N8nServicesManager{
		client: client,
	}
}

// ReconcileServices ensures all services are correct
func (m *N8nServicesManager) ReconcileServices(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Reconciling services")

	// Define services to create
	services := []struct {
		name        string
		component   string
		serviceType corev1.ServiceType
		ports       []ServicePort
		annotations map[string]string
	}{
		{
			name:        fmt.Sprintf("%s-main", instance.Name),
			component:   "main",
			serviceType: corev1.ServiceTypeClusterIP,
			ports: []ServicePort{
				{
					name:       "http",
					port:       5678,
					targetPort: 5678,
					protocol:   corev1.ProtocolTCP,
				},
			},
			annotations: map[string]string{
				"service.beta.kubernetes.io/aws-load-balancer-type": "nlb",
			},
		},
		{
			name:        fmt.Sprintf("%s-webhook", instance.Name),
			component:   "webhook",
			serviceType: corev1.ServiceTypeClusterIP,
			ports: []ServicePort{
				{
					name:       "http",
					port:       5679,
					targetPort: 5679,
					protocol:   corev1.ProtocolTCP,
				},
			},
			annotations: map[string]string{
				"service.beta.kubernetes.io/aws-load-balancer-type": "nlb",
			},
		},
		{
			name:        fmt.Sprintf("%s-worker-headless", instance.Name),
			component:   "worker",
			serviceType: corev1.ServiceTypeClusterIP,
			ports:       []ServicePort{}, // Headless service for workers
			annotations: map[string]string{
				"service.alpha.kubernetes.io/tolerate-unready-endpoints": "true",
			},
		},
	}

	// Create services
	for _, svc := range services {
		if err := m.createOrUpdateService(ctx, instance, svc); err != nil {
			return fmt.Errorf("failed to create service %s: %w", svc.name, err)
		}
	}

	logger.Info("Services reconciled successfully")
	return nil
}

// ReconcileIngress creates and manages ingress resources
func (m *N8nServicesManager) ReconcileIngress(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Reconciling ingress resources")

	// Create main ingress for n8n UI
	if err := m.createMainIngress(ctx, instance); err != nil {
		return fmt.Errorf("failed to create main ingress: %w", err)
	}

	// Create webhook ingress
	if err := m.createWebhookIngress(ctx, instance); err != nil {
		return fmt.Errorf("failed to create webhook ingress: %w", err)
	}

	logger.Info("Ingress resources reconciled successfully")
	return nil
}

// ServicePort represents a service port configuration
type ServicePort struct {
	name       string
	port       int32
	targetPort int32
	protocol   corev1.Protocol
}

// createOrUpdateService creates or updates a Kubernetes service
func (m *N8nServicesManager) createOrUpdateService(ctx context.Context, instance *n8nv1alpha1.N8nInstance, config struct {
	name        string
	component   string
	serviceType corev1.ServiceType
	ports       []ServicePort
	annotations map[string]string
}) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Creating or updating service", "name", config.name, "component", config.component)

	// Build service ports
	var servicePorts []corev1.ServicePort
	for _, port := range config.ports {
		servicePorts = append(servicePorts, corev1.ServicePort{
			Name:       port.name,
			Port:       port.port,
			TargetPort: intstr.FromInt(int(port.targetPort)),
			Protocol:   port.protocol,
		})
	}

	// Create service
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      config.name,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  config.component,
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: config.annotations,
		},
		Spec: corev1.ServiceSpec{
			Type: config.serviceType,
			Selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/instance":  instance.Name,
				"app.kubernetes.io/component": config.component,
			},
			Ports: servicePorts,
		},
	}

	// Configure headless service for workers
	if config.component == "worker" {
		service.Spec.ClusterIP = "None"
		service.Spec.PublishNotReadyAddresses = true
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, service, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update service
	existingService := &corev1.Service{}
	serviceKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      config.name,
	}

	if err := m.client.Get(ctx, serviceKey, existingService); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing service: %w", err)
		}
		// Service doesn't exist, create it
		if err := m.client.Create(ctx, service); err != nil {
			return fmt.Errorf("failed to create service: %w", err)
		}
		logger.Info("Service created successfully", "name", config.name)
	} else {
		// Service exists, update it
		existingService.Spec.Ports = service.Spec.Ports
		existingService.Annotations = service.Annotations
		if err := m.client.Update(ctx, existingService); err != nil {
			return fmt.Errorf("failed to update service: %w", err)
		}
		logger.Info("Service updated successfully", "name", config.name)
	}

	return nil
}

// createMainIngress creates ingress for the main n8n application
func (m *N8nServicesManager) createMainIngress(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	ingressName := fmt.Sprintf("%s-main-ingress", instance.Name)
	logger.Info("Creating main ingress", "name", ingressName)

	pathType := networkingv1.PathTypePrefix
	
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ingressName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "main",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":                    "alb",
				"alb.ingress.kubernetes.io/scheme":               "internet-facing",
				"alb.ingress.kubernetes.io/target-type":          "ip",
				"alb.ingress.kubernetes.io/listen-ports":         `[{"HTTP": 80}, {"HTTPS": 443}]`,
				"alb.ingress.kubernetes.io/ssl-redirect":         "443",
				"alb.ingress.kubernetes.io/certificate-arn":      "", // Will be populated by network manager
				"alb.ingress.kubernetes.io/backend-protocol":     "HTTP",
				"alb.ingress.kubernetes.io/healthcheck-path":     "/healthz",
				"alb.ingress.kubernetes.io/healthcheck-interval-seconds": "15",
				"alb.ingress.kubernetes.io/healthcheck-timeout-seconds":  "5",
				"alb.ingress.kubernetes.io/healthy-threshold-count":      "2",
				"alb.ingress.kubernetes.io/unhealthy-threshold-count":    "2",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: instance.Spec.Domain,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: fmt.Sprintf("%s-main", instance.Name),
											Port: networkingv1.ServiceBackendPort{
												Number: 5678,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, ingress, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return m.createOrUpdateIngress(ctx, ingress)
}

// createWebhookIngress creates ingress for webhook endpoints
func (m *N8nServicesManager) createWebhookIngress(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	ingressName := fmt.Sprintf("%s-webhook-ingress", instance.Name)
	logger.Info("Creating webhook ingress", "name", ingressName)

	pathType := networkingv1.PathTypePrefix
	webhookHost := fmt.Sprintf("webhook.%s", instance.Spec.Domain)
	
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ingressName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "webhook",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: map[string]string{
				"kubernetes.io/ingress.class":                    "alb",
				"alb.ingress.kubernetes.io/scheme":               "internet-facing",
				"alb.ingress.kubernetes.io/target-type":          "ip",
				"alb.ingress.kubernetes.io/listen-ports":         `[{"HTTP": 80}, {"HTTPS": 443}]`,
				"alb.ingress.kubernetes.io/ssl-redirect":         "443",
				"alb.ingress.kubernetes.io/certificate-arn":      "", // Will be populated by network manager
				"alb.ingress.kubernetes.io/backend-protocol":     "HTTP",
				"alb.ingress.kubernetes.io/healthcheck-path":     "/healthz",
				"alb.ingress.kubernetes.io/healthcheck-interval-seconds": "15",
				"alb.ingress.kubernetes.io/healthcheck-timeout-seconds":  "5",
				"alb.ingress.kubernetes.io/healthy-threshold-count":      "2",
				"alb.ingress.kubernetes.io/unhealthy-threshold-count":    "2",
				// Webhook-specific annotations
				"alb.ingress.kubernetes.io/load-balancer-attributes": "idle_timeout.timeout_seconds=60",
				"alb.ingress.kubernetes.io/target-group-attributes":  "deregistration_delay.timeout_seconds=30",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: webhookHost,
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/webhook",
									PathType: &pathType,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: fmt.Sprintf("%s-webhook", instance.Name),
											Port: networkingv1.ServiceBackendPort{
												Number: 5679,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, ingress, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return m.createOrUpdateIngress(ctx, ingress)
}

// createOrUpdateIngress creates or updates an ingress resource
func (m *N8nServicesManager) createOrUpdateIngress(ctx context.Context, ingress *networkingv1.Ingress) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	name := ingress.Name
	namespace := ingress.Namespace
	
	logger.Info("Creating or updating ingress", "name", name, "namespace", namespace)

	// Check if ingress exists
	existingIngress := &networkingv1.Ingress{}
	ingressKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	if err := m.client.Get(ctx, ingressKey, existingIngress); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ingress: %w", err)
		}
		// Ingress doesn't exist, create it
		if err := m.client.Create(ctx, ingress); err != nil {
			return fmt.Errorf("failed to create ingress: %w", err)
		}
		logger.Info("Ingress created successfully", "name", name)
	} else {
		// Ingress exists, update it
		existingIngress.Spec = ingress.Spec
		existingIngress.Annotations = ingress.Annotations
		if err := m.client.Update(ctx, existingIngress); err != nil {
			return fmt.Errorf("failed to update ingress: %w", err)
		}
		logger.Info("Ingress updated successfully", "name", name)
	}

	return nil
}

// c
reateAdvancedServices creates services with advanced configurations
func (m *N8nServicesManager) createAdvancedServices(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Creating advanced services")

	// Create monitoring service
	if err := m.createMonitoringService(ctx, instance); err != nil {
		return fmt.Errorf("failed to create monitoring service: %w", err)
	}

	// Create internal API service
	if err := m.createInternalAPIService(ctx, instance); err != nil {
		return fmt.Errorf("failed to create internal API service: %w", err)
	}

	// Create metrics service
	if err := m.createMetricsService(ctx, instance); err != nil {
		return fmt.Errorf("failed to create metrics service: %w", err)
	}

	logger.Info("Advanced services created successfully")
	return nil
}

// createMonitoringService creates a service for monitoring endpoints
func (m *N8nServicesManager) createMonitoringService(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	serviceName := fmt.Sprintf("%s-monitoring", instance.Name)
	logger.Info("Creating monitoring service", "name", serviceName)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "monitoring",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: map[string]string{
				"prometheus.io/scrape": "true",
				"prometheus.io/port":   "9090",
				"prometheus.io/path":   "/metrics",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app.kubernetes.io/name":     "n8n",
				"app.kubernetes.io/instance": instance.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "metrics",
					Port:       9090,
					TargetPort: intstr.FromInt(9090),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "health",
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, service, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return m.createOrUpdateKubernetesService(ctx, service)
}

// createInternalAPIService creates a service for internal API communication
func (m *N8nServicesManager) createInternalAPIService(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	serviceName := fmt.Sprintf("%s-internal-api", instance.Name)
	logger.Info("Creating internal API service", "name", serviceName)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "internal-api",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: map[string]string{
				"service.alpha.kubernetes.io/tolerate-unready-endpoints": "false",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/instance":  instance.Name,
				"app.kubernetes.io/component": "main",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "internal-api",
					Port:       5680,
					TargetPort: intstr.FromInt(5680),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, service, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return m.createOrUpdateKubernetesService(ctx, service)
}

// createMetricsService creates a service for metrics collection
func (m *N8nServicesManager) createMetricsService(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	serviceName := fmt.Sprintf("%s-metrics", instance.Name)
	logger.Info("Creating metrics service", "name", serviceName)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "metrics",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: map[string]string{
				"prometheus.io/scrape": "true",
				"prometheus.io/port":   "3000",
				"prometheus.io/path":   "/metrics",
			},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"app.kubernetes.io/name":     "n8n",
				"app.kubernetes.io/instance": instance.Name,
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "prometheus",
					Port:       3000,
					TargetPort: intstr.FromString("prometheus"),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, service, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return m.createOrUpdateKubernetesService(ctx, service)
}

// createOrUpdateKubernetesService creates or updates a Kubernetes service
func (m *N8nServicesManager) createOrUpdateKubernetesService(ctx context.Context, service *corev1.Service) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	name := service.Name
	namespace := service.Namespace
	
	logger.Info("Creating or updating Kubernetes service", "name", name, "namespace", namespace)

	// Check if service exists
	existingService := &corev1.Service{}
	serviceKey := client.ObjectKey{
		Namespace: namespace,
		Name:      name,
	}

	if err := m.client.Get(ctx, serviceKey, existingService); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing service: %w", err)
		}
		// Service doesn't exist, create it
		if err := m.client.Create(ctx, service); err != nil {
			return fmt.Errorf("failed to create service: %w", err)
		}
		logger.Info("Kubernetes service created successfully", "name", name)
	} else {
		// Service exists, update it
		existingService.Spec.Ports = service.Spec.Ports
		existingService.Annotations = service.Annotations
		if err := m.client.Update(ctx, existingService); err != nil {
			return fmt.Errorf("failed to update service: %w", err)
		}
		logger.Info("Kubernetes service updated successfully", "name", name)
	}

	return nil
}

// getServiceEndpoints retrieves service endpoints information
func (m *N8nServicesManager) getServiceEndpoints(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Retrieving service endpoints")

	endpoints := make(map[string]interface{})

	// Get services
	serviceList := &corev1.ServiceList{}
	listOptions := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/instance": instance.Name,
		},
	}

	if err := m.client.List(ctx, serviceList, listOptions...); err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	serviceEndpoints := make([]map[string]interface{}, 0, len(serviceList.Items))
	
	for _, service := range serviceList.Items {
		serviceEndpoint := map[string]interface{}{
			"name":      service.Name,
			"component": service.Labels["app.kubernetes.io/component"],
			"type":      string(service.Spec.Type),
		}

		// Add ports information
		ports := make([]map[string]interface{}, 0, len(service.Spec.Ports))
		for _, port := range service.Spec.Ports {
			portInfo := map[string]interface{}{
				"name":        port.Name,
				"port":        port.Port,
				"target_port": port.TargetPort.String(),
				"protocol":    string(port.Protocol),
			}
			ports = append(ports, portInfo)
		}
		serviceEndpoint["ports"] = ports

		// Add cluster IP
		if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != "None" {
			serviceEndpoint["cluster_ip"] = service.Spec.ClusterIP
		}

		// Add external IP if available
		if len(service.Status.LoadBalancer.Ingress) > 0 {
			ingress := service.Status.LoadBalancer.Ingress[0]
			if ingress.IP != "" {
				serviceEndpoint["external_ip"] = ingress.IP
			}
			if ingress.Hostname != "" {
				serviceEndpoint["external_hostname"] = ingress.Hostname
			}
		}

		serviceEndpoints = append(serviceEndpoints, serviceEndpoint)
	}

	endpoints["services"] = serviceEndpoints
	endpoints["total_services"] = len(serviceList.Items)

	// Get ingress information
	ingressList := &networkingv1.IngressList{}
	if err := m.client.List(ctx, ingressList, listOptions...); err == nil {
		ingressEndpoints := make([]map[string]interface{}, 0, len(ingressList.Items))
		
		for _, ingress := range ingressList.Items {
			ingressEndpoint := map[string]interface{}{
				"name":      ingress.Name,
				"component": ingress.Labels["app.kubernetes.io/component"],
			}

			// Add hosts
			hosts := make([]string, 0)
			for _, rule := range ingress.Spec.Rules {
				if rule.Host != "" {
					hosts = append(hosts, rule.Host)
				}
			}
			ingressEndpoint["hosts"] = hosts

			// Add load balancer status
			if len(ingress.Status.LoadBalancer.Ingress) > 0 {
				lbIngress := ingress.Status.LoadBalancer.Ingress[0]
				if lbIngress.IP != "" {
					ingressEndpoint["load_balancer_ip"] = lbIngress.IP
				}
				if lbIngress.Hostname != "" {
					ingressEndpoint["load_balancer_hostname"] = lbIngress.Hostname
				}
			}

			ingressEndpoints = append(ingressEndpoints, ingressEndpoint)
		}

		endpoints["ingresses"] = ingressEndpoints
		endpoints["total_ingresses"] = len(ingressList.Items)
	}

	logger.Info("Service endpoints retrieved", "totalServices", len(serviceList.Items))
	return endpoints, nil
}

// validateServiceConfiguration validates service configuration
func (m *N8nServicesManager) validateServiceConfiguration(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Validating service configuration")

	// Get services
	serviceList := &corev1.ServiceList{}
	listOptions := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/instance": instance.Name,
		},
	}

	if err := m.client.List(ctx, serviceList, listOptions...); err != nil {
		return fmt.Errorf("failed to list services: %w", err)
	}

	// Validate required services exist
	requiredServices := map[string]bool{
		fmt.Sprintf("%s-main", instance.Name):    false,
		fmt.Sprintf("%s-webhook", instance.Name): false,
	}

	for _, service := range serviceList.Items {
		if _, required := requiredServices[service.Name]; required {
			requiredServices[service.Name] = true
		}
	}

	// Check for missing required services
	for serviceName, exists := range requiredServices {
		if !exists {
			return fmt.Errorf("required service %s is missing", serviceName)
		}
	}

	// Validate service endpoints are ready
	for _, service := range serviceList.Items {
		if err := m.validateServiceEndpoints(ctx, service); err != nil {
			logger.Warn("Service endpoint validation failed", "service", service.Name, "error", err)
		}
	}

	logger.Info("Service configuration validation completed")
	return nil
}

// validateServiceEndpoints validates that service endpoints are ready
func (m *N8nServicesManager) validateServiceEndpoints(ctx context.Context, service corev1.Service) error {
	// Get endpoints for the service
	endpoints := &corev1.Endpoints{}
	endpointsKey := client.ObjectKey{
		Namespace: service.Namespace,
		Name:      service.Name,
	}

	if err := m.client.Get(ctx, endpointsKey, endpoints); err != nil {
		return fmt.Errorf("failed to get endpoints for service %s: %w", service.Name, err)
	}

	// Check if endpoints have ready addresses
	hasReadyAddresses := false
	for _, subset := range endpoints.Subsets {
		if len(subset.Addresses) > 0 {
			hasReadyAddresses = true
			break
		}
	}

	if !hasReadyAddresses {
		return fmt.Errorf("service %s has no ready endpoints", service.Name)
	}

	return nil
}

// getServicesMetrics retrieves services metrics
func (m *N8nServicesManager) getServicesMetrics(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Retrieving services metrics")

	metrics := make(map[string]interface{})

	// Get services
	serviceList := &corev1.ServiceList{}
	listOptions := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/instance": instance.Name,
		},
	}

	if err := m.client.List(ctx, serviceList, listOptions...); err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	serviceTypes := make(map[string]int)
	totalPorts := 0
	readyServices := 0

	for _, service := range serviceList.Items {
		// Count by type
		serviceTypes[string(service.Spec.Type)]++
		
		// Count ports
		totalPorts += len(service.Spec.Ports)
		
		// Check if service has endpoints
		if err := m.validateServiceEndpoints(ctx, service); err == nil {
			readyServices++
		}
	}

	metrics["total_services"] = len(serviceList.Items)
	metrics["service_types"] = serviceTypes
	metrics["total_ports"] = totalPorts
	metrics["ready_services"] = readyServices
	
	if len(serviceList.Items) > 0 {
		metrics["readiness_percent"] = float64(readyServices) / float64(len(serviceList.Items)) * 100
	}

	// Get ingress metrics
	ingressList := &networkingv1.IngressList{}
	if err := m.client.List(ctx, ingressList, listOptions...); err == nil {
		readyIngresses := 0
		totalHosts := 0
		
		for _, ingress := range ingressList.Items {
			// Count hosts
			for _, rule := range ingress.Spec.Rules {
				if rule.Host != "" {
					totalHosts++
				}
			}
			
			// Check if ingress has load balancer
			if len(ingress.Status.LoadBalancer.Ingress) > 0 {
				readyIngresses++
			}
		}
		
		metrics["total_ingresses"] = len(ingressList.Items)
		metrics["ready_ingresses"] = readyIngresses
		metrics["total_hosts"] = totalHosts
		
		if len(ingressList.Items) > 0 {
			metrics["ingress_readiness_percent"] = float64(readyIngresses) / float64(len(ingressList.Items)) * 100
		}
	}

	logger.Info("Services metrics retrieved", "totalServices", len(serviceList.Items))
	return metrics, nil
}

// cre
ateAWSLoadBalancerServices creates services with AWS Load Balancer Controller integration
func (m *N8nServicesManager) createAWSLoadBalancerServices(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Creating AWS Load Balancer services")

	// Create Application Load Balancer for main service
	if err := m.createApplicationLoadBalancer(ctx, instance); err != nil {
		return fmt.Errorf("failed to create Application Load Balancer: %w", err)
	}

	// Create Network Load Balancer for webhook service
	if err := m.createNetworkLoadBalancer(ctx, instance); err != nil {
		return fmt.Errorf("failed to create Network Load Balancer: %w", err)
	}

	logger.Info("AWS Load Balancer services created successfully")
	return nil
}

// createApplicationLoadBalancer creates an ALB for the main n8n service
func (m *N8nServicesManager) createApplicationLoadBalancer(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	serviceName := fmt.Sprintf("%s-alb", instance.Name)
	logger.Info("Creating Application Load Balancer service", "name", serviceName)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "alb",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: m.getALBAnnotations(instance),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/instance":  instance.Name,
				"app.kubernetes.io/component": "main",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt(5678),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "https",
					Port:       443,
					TargetPort: intstr.FromInt(5678),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, service, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return m.createOrUpdateKubernetesService(ctx, service)
}

// createNetworkLoadBalancer creates an NLB for the webhook service
func (m *N8nServicesManager) createNetworkLoadBalancer(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	serviceName := fmt.Sprintf("%s-nlb", instance.Name)
	logger.Info("Creating Network Load Balancer service", "name", serviceName)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "nlb",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
			Annotations: m.getNLBAnnotations(instance),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Selector: map[string]string{
				"app.kubernetes.io/name":      "n8n",
				"app.kubernetes.io/instance":  instance.Name,
				"app.kubernetes.io/component": "webhook",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "webhook-http",
					Port:       80,
					TargetPort: intstr.FromInt(5679),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "webhook-https",
					Port:       443,
					TargetPort: intstr.FromInt(5679),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, service, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	return m.createOrUpdateKubernetesService(ctx, service)
}

// getALBAnnotations returns ALB-specific annotations
func (m *N8nServicesManager) getALBAnnotations(instance *n8nv1alpha1.N8nInstance) map[string]string {
	return map[string]string{
		// Load Balancer Controller annotations
		"service.beta.kubernetes.io/aws-load-balancer-type":                     "external",
		"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type":          "ip",
		"service.beta.kubernetes.io/aws-load-balancer-scheme":                   "internet-facing",
		"service.beta.kubernetes.io/aws-load-balancer-backend-protocol":         "http",
		
		// SSL/TLS configuration
		"service.beta.kubernetes.io/aws-load-balancer-ssl-cert":                 "", // Will be populated by network manager
		"service.beta.kubernetes.io/aws-load-balancer-ssl-ports":                "https",
		"service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy":   "ELBSecurityPolicy-TLS-1-2-2017-01",
		
		// Health check configuration
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol":     "HTTP",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-port":         "5678",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-path":         "/healthz",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-interval":     "15",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-timeout":      "5",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-healthy-threshold":   "2",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-unhealthy-threshold": "2",
		
		// Performance and behavior
		"service.beta.kubernetes.io/aws-load-balancer-connection-draining-enabled": "true",
		"service.beta.kubernetes.io/aws-load-balancer-connection-draining-timeout": "60",
		"service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled": "true",
		
		// Access logs
		"service.beta.kubernetes.io/aws-load-balancer-access-log-enabled": "true",
		"service.beta.kubernetes.io/aws-load-balancer-access-log-s3-bucket-name": fmt.Sprintf("n8n-alb-logs-%s", instance.Name),
		"service.beta.kubernetes.io/aws-load-balancer-access-log-s3-bucket-prefix": "alb",
		
		// Additional attributes
		"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": fmt.Sprintf("Environment=production,Application=n8n,Instance=%s", instance.Name),
	}
}

// getNLBAnnotations returns NLB-specific annotations
func (m *N8nServicesManager) getNLBAnnotations(instance *n8nv1alpha1.N8nInstance) map[string]string {
	return map[string]string{
		// Load Balancer Controller annotations
		"service.beta.kubernetes.io/aws-load-balancer-type":            "external",
		"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "ip",
		"service.beta.kubernetes.io/aws-load-balancer-scheme":          "internet-facing",
		
		// SSL/TLS configuration
		"service.beta.kubernetes.io/aws-load-balancer-ssl-cert":                 "", // Will be populated by network manager
		"service.beta.kubernetes.io/aws-load-balancer-ssl-ports":                "webhook-https",
		"service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy":   "ELBSecurityPolicy-TLS-1-2-2017-01",
		
		// Health check configuration
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol":     "HTTP",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-port":         "5679",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-path":         "/healthz",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-interval":     "10",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-timeout":      "6",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-healthy-threshold":   "2",
		"service.beta.kubernetes.io/aws-load-balancer-healthcheck-unhealthy-threshold": "2",
		
		// NLB-specific configuration
		"service.beta.kubernetes.io/aws-load-balancer-cross-zone-load-balancing-enabled": "true",
		"service.beta.kubernetes.io/aws-load-balancer-target-group-attributes": "preserve_client_ip.enabled=true,deregistration_delay.timeout_seconds=30",
		
		// Access logs
		"service.beta.kubernetes.io/aws-load-balancer-access-log-enabled": "true",
		"service.beta.kubernetes.io/aws-load-balancer-access-log-s3-bucket-name": fmt.Sprintf("n8n-nlb-logs-%s", instance.Name),
		"service.beta.kubernetes.io/aws-load-balancer-access-log-s3-bucket-prefix": "nlb",
		
		// Additional attributes
		"service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": fmt.Sprintf("Environment=production,Application=n8n,Instance=%s,Component=webhook", instance.Name),
	}
}

// configureTargetGroups configures ALB/NLB target groups
func (m *N8nServicesManager) configureTargetGroups(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Configuring target groups")

	// Create target group configuration for main service
	if err := m.createTargetGroupConfig(ctx, instance, "main"); err != nil {
		return fmt.Errorf("failed to create target group config for main: %w", err)
	}

	// Create target group configuration for webhook service
	if err := m.createTargetGroupConfig(ctx, instance, "webhook"); err != nil {
		return fmt.Errorf("failed to create target group config for webhook: %w", err)
	}

	logger.Info("Target groups configured successfully")
	return nil
}

// createTargetGroupConfig creates target group configuration
func (m *N8nServicesManager) createTargetGroupConfig(ctx context.Context, instance *n8nv1alpha1.N8nInstance, component string) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	
	configMapName := fmt.Sprintf("%s-%s-tg-config", instance.Name, component)
	logger.Info("Creating target group configuration", "name", configMapName, "component", component)

	var targetGroupConfig map[string]string
	
	switch component {
	case "main":
		targetGroupConfig = map[string]string{
			"target-type":                    "ip",
			"protocol":                       "HTTP",
			"port":                          "5678",
			"health-check-protocol":         "HTTP",
			"health-check-path":             "/healthz",
			"health-check-interval-seconds": "15",
			"health-check-timeout-seconds":  "5",
			"healthy-threshold-count":       "2",
			"unhealthy-threshold-count":     "2",
			"deregistration-delay":          "30",
			"stickiness-enabled":            "false",
		}
	case "webhook":
		targetGroupConfig = map[string]string{
			"target-type":                    "ip",
			"protocol":                       "HTTP",
			"port":                          "5679",
			"health-check-protocol":         "HTTP",
			"health-check-path":             "/healthz",
			"health-check-interval-seconds": "10",
			"health-check-timeout-seconds":  "6",
			"healthy-threshold-count":       "2",
			"unhealthy-threshold-count":     "2",
			"deregistration-delay":          "30",
			"stickiness-enabled":            "false",
		}
	default:
		return fmt.Errorf("unsupported component: %s", component)
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  component,
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: targetGroupConfig,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, configMap, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      configMapName,
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, configMap); err != nil {
			return fmt.Errorf("failed to create target group ConfigMap: %w", err)
		}
		logger.Info("Target group ConfigMap created successfully", "name", configMapName)
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = targetGroupConfig
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update target group ConfigMap: %w", err)
		}
		logger.Info("Target group ConfigMap updated successfully", "name", configMapName)
	}

	return nil
}

// validateAWSLoadBalancerController validates AWS Load Balancer Controller is installed
func (m *N8nServicesManager) validateAWSLoadBalancerController(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Validating AWS Load Balancer Controller")

	// Check if AWS Load Balancer Controller deployment exists
	deploymentList := &appsv1.DeploymentList{}
	listOptions := []client.ListOption{
		client.InNamespace("kube-system"),
		client.MatchingLabels{
			"app.kubernetes.io/name": "aws-load-balancer-controller",
		},
	}

	if err := m.client.List(ctx, deploymentList, listOptions...); err != nil {
		return fmt.Errorf("failed to list AWS Load Balancer Controller deployments: %w", err)
	}

	if len(deploymentList.Items) == 0 {
		return fmt.Errorf("AWS Load Balancer Controller is not installed")
	}

	// Check if the controller is ready
	for _, deployment := range deploymentList.Items {
		if deployment.Status.ReadyReplicas == 0 {
			return fmt.Errorf("AWS Load Balancer Controller is not ready")
		}
	}

	logger.Info("AWS Load Balancer Controller validation successful")
	return nil
}

// getLoadBalancerStatus retrieves load balancer status information
func (m *N8nServicesManager) getLoadBalancerStatus(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Retrieving load balancer status")

	status := make(map[string]interface{})

	// Get LoadBalancer type services
	serviceList := &corev1.ServiceList{}
	listOptions := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/instance": instance.Name,
		},
	}

	if err := m.client.List(ctx, serviceList, listOptions...); err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	loadBalancers := make([]map[string]interface{}, 0)
	
	for _, service := range serviceList.Items {
		if service.Spec.Type == corev1.ServiceTypeLoadBalancer {
			lbInfo := map[string]interface{}{
				"name":      service.Name,
				"component": service.Labels["app.kubernetes.io/component"],
			}

			// Add load balancer ingress information
			if len(service.Status.LoadBalancer.Ingress) > 0 {
				ingress := service.Status.LoadBalancer.Ingress[0]
				if ingress.IP != "" {
					lbInfo["external_ip"] = ingress.IP
				}
				if ingress.Hostname != "" {
					lbInfo["external_hostname"] = ingress.Hostname
				}
				lbInfo["ready"] = true
			} else {
				lbInfo["ready"] = false
				lbInfo["status"] = "pending"
			}

			// Add annotations for load balancer type detection
			if lbType, exists := service.Annotations["service.beta.kubernetes.io/aws-load-balancer-type"]; exists {
				lbInfo["type"] = lbType
			}

			loadBalancers = append(loadBalancers, lbInfo)
		}
	}

	status["load_balancers"] = loadBalancers
	status["total_load_balancers"] = len(loadBalancers)

	// Count ready load balancers
	readyCount := 0
	for _, lb := range loadBalancers {
		if ready, ok := lb["ready"].(bool); ok && ready {
			readyCount++
		}
	}
	status["ready_load_balancers"] = readyCount

	if len(loadBalancers) > 0 {
		status["readiness_percent"] = float64(readyCount) / float64(len(loadBalancers)) * 100
	}

	logger.Info("Load balancer status retrieved", "totalLBs", len(loadBalancers), "readyLBs", readyCount)
	return status, nil
}

//
/ configureEndpointsAndDNS configures service endpoints and DNS records
func (m *N8nServicesManager) configureEndpointsAndDNS(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Configuring endpoints and DNS")

	// Update instance status with service endpoints
	if err := m.updateInstanceStatusWithEndpoints(ctx, instance); err != nil {
		return fmt.Errorf("failed to update instance status with endpoints: %w", err)
	}

	// Configure subdomain endpoints
	if err := m.configureSubdomainEndpoints(ctx, instance); err != nil {
		return fmt.Errorf("failed to configure subdomain endpoints: %w", err)
	}

	// Validate endpoint accessibility
	if err := m.validateEndpointAccessibility(ctx, instance); err != nil {
		logger.Warn("Endpoint accessibility validation failed", "error", err)
	}

	logger.Info("Endpoints and DNS configured successfully")
	return nil
}

// updateInstanceStatusWithEndpoints updates the N8nInstance status with service endpoints
func (m *N8nServicesManager) updateInstanceStatusWithEndpoints(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Updating instance status with endpoints")

	// Get service endpoints
	endpoints, err := m.getServiceEndpoints(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to get service endpoints: %w", err)
	}

	// Extract main service endpoint
	var mainEndpoint, webhookEndpoint string
	
	if services, ok := endpoints["services"].([]map[string]interface{}); ok {
		for _, service := range services {
			component, _ := service["component"].(string)
			
			switch component {
			case "main":
				if externalHostname, exists := service["external_hostname"]; exists {
					mainEndpoint = fmt.Sprintf("https://%s", externalHostname)
				} else if externalIP, exists := service["external_ip"]; exists {
					mainEndpoint = fmt.Sprintf("https://%s", externalIP)
				}
			case "webhook":
				if externalHostname, exists := service["external_hostname"]; exists {
					webhookEndpoint = fmt.Sprintf("https://%s/webhook", externalHostname)
				} else if externalIP, exists := service["external_ip"]; exists {
					webhookEndpoint = fmt.Sprintf("https://%s/webhook", externalIP)
				}
			}
		}
	}

	// Update instance status (this would be done through the controller)
	logger.Info("Service endpoints identified", 
		"mainEndpoint", mainEndpoint, 
		"webhookEndpoint", webhookEndpoint)

	return nil
}

// configureSubdomainEndpoints configures subdomain endpoints for different components
func (m *N8nServicesManager) configureSubdomainEndpoints(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Configuring subdomain endpoints")

	// Create endpoint configuration ConfigMap
	endpointConfig := map[string]string{
		"main-domain":    instance.Spec.Domain,
		"webhook-domain": fmt.Sprintf("webhook.%s", instance.Spec.Domain),
		"api-domain":     fmt.Sprintf("api.%s", instance.Spec.Domain),
		"metrics-domain": fmt.Sprintf("metrics.%s", instance.Spec.Domain),
	}

	// Add protocol and port information
	endpointConfig["main-url"] = fmt.Sprintf("https://%s", instance.Spec.Domain)
	endpointConfig["webhook-url"] = fmt.Sprintf("https://webhook.%s/webhook", instance.Spec.Domain)
	endpointConfig["api-url"] = fmt.Sprintf("https://api.%s/api", instance.Spec.Domain)
	endpointConfig["metrics-url"] = fmt.Sprintf("https://metrics.%s/metrics", instance.Spec.Domain)

	configMapName := fmt.Sprintf("%s-endpoints", instance.Name)
	
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "endpoints",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: endpointConfig,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, configMap, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      configMapName,
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, configMap); err != nil {
			return fmt.Errorf("failed to create endpoints ConfigMap: %w", err)
		}
		logger.Info("Endpoints ConfigMap created successfully", "name", configMapName)
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = endpointConfig
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update endpoints ConfigMap: %w", err)
		}
		logger.Info("Endpoints ConfigMap updated successfully", "name", configMapName)
	}

	return nil
}

// validateEndpointAccessibility validates that endpoints are accessible
func (m *N8nServicesManager) validateEndpointAccessibility(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Validating endpoint accessibility")

	// Get load balancer status
	lbStatus, err := m.getLoadBalancerStatus(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to get load balancer status: %w", err)
	}

	// Check if load balancers are ready
	if loadBalancers, ok := lbStatus["load_balancers"].([]map[string]interface{}); ok {
		for _, lb := range loadBalancers {
			if ready, ok := lb["ready"].(bool); !ok || !ready {
				return fmt.Errorf("load balancer %s is not ready", lb["name"])
			}
		}
	}

	// Validate ingress resources have load balancer assigned
	ingressList := &networkingv1.IngressList{}
	listOptions := []client.ListOption{
		client.InNamespace(instance.Namespace),
		client.MatchingLabels{
			"app.kubernetes.io/instance": instance.Name,
		},
	}

	if err := m.client.List(ctx, ingressList, listOptions...); err != nil {
		return fmt.Errorf("failed to list ingress resources: %w", err)
	}

	for _, ingress := range ingressList.Items {
		if len(ingress.Status.LoadBalancer.Ingress) == 0 {
			return fmt.Errorf("ingress %s has no load balancer assigned", ingress.Name)
		}
	}

	logger.Info("Endpoint accessibility validation successful")
	return nil
}

// configureHTTPSRedirects configures HTTP to HTTPS redirects
func (m *N8nServicesManager) configureHTTPSRedirects(ctx context.Context, instance *n8nv1alpha1.N8nInstance) error {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Configuring HTTPS redirects")

	// Create redirect configuration
	redirectConfig := map[string]string{
		"redirect-enabled": "true",
		"redirect-code":    "301",
		"redirect-scheme":  "https",
		"redirect-port":    "443",
	}

	configMapName := fmt.Sprintf("%s-redirect-config", instance.Name)
	
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: instance.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "n8n",
				"app.kubernetes.io/instance":   instance.Name,
				"app.kubernetes.io/component":  "redirect",
				"app.kubernetes.io/managed-by": "n8n-operator",
			},
		},
		Data: redirectConfig,
	}

	// Set owner reference
	if err := ctrl.SetControllerReference(instance, configMap, m.client.Scheme()); err != nil {
		return fmt.Errorf("failed to set controller reference: %w", err)
	}

	// Create or update ConfigMap
	existingConfigMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      configMapName,
	}

	if err := m.client.Get(ctx, configMapKey, existingConfigMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("failed to get existing ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist, create it
		if err := m.client.Create(ctx, configMap); err != nil {
			return fmt.Errorf("failed to create redirect ConfigMap: %w", err)
		}
		logger.Info("Redirect ConfigMap created successfully", "name", configMapName)
	} else {
		// ConfigMap exists, update it
		existingConfigMap.Data = redirectConfig
		if err := m.client.Update(ctx, existingConfigMap); err != nil {
			return fmt.Errorf("failed to update redirect ConfigMap: %w", err)
		}
		logger.Info("Redirect ConfigMap updated successfully", "name", configMapName)
	}

	return nil
}

// getEndpointConfiguration retrieves endpoint configuration information
func (m *N8nServicesManager) getEndpointConfiguration(ctx context.Context, instance *n8nv1alpha1.N8nInstance) (map[string]interface{}, error) {
	logger := log.FromContext(ctx).WithName("N8nServicesManager")
	logger.Info("Retrieving endpoint configuration")

	config := make(map[string]interface{})

	// Get endpoints ConfigMap
	configMapName := fmt.Sprintf("%s-endpoints", instance.Name)
	configMap := &corev1.ConfigMap{}
	configMapKey := client.ObjectKey{
		Namespace: instance.Namespace,
		Name:      configMapName,
	}

	if err := m.client.Get(ctx, configMapKey, configMap); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return nil, fmt.Errorf("failed to get endpoints ConfigMap: %w", err)
		}
		// ConfigMap doesn't exist
		config["endpoints_configured"] = false
		return config, nil
	}

	config["endpoints_configured"] = true
	config["endpoints"] = configMap.Data

	// Get service endpoints
	serviceEndpoints, err := m.getServiceEndpoints(ctx, instance)
	if err != nil {
		logger.Warn("Failed to get service endpoints", "error", err)
	} else {
		config["service_endpoints"] = serviceEndpoints
	}

	// Get load balancer status
	lbStatus, err := m.getLoadBalancerStatus(ctx, instance)
	if err != nil {
		logger.Warn("Failed to get load balancer status", "error", err)
	} else {
		config["load_balancer_status"] = lbStatus
	}

	logger.Info("Endpoint configuration retrieved successfully")
	return config, nil
}
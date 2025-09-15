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

//go:build performance
// +build performance

package performance

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

// BenchmarkSuite holds benchmark test setup
type BenchmarkSuite struct {
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
	clientset *kubernetes.Clientset
	namespace string
}

// setupBenchmark sets up the benchmark environment
func setupBenchmark(b *testing.B) *BenchmarkSuite {
	suite := &BenchmarkSuite{
		namespace: fmt.Sprintf("bench-%d", time.Now().Unix()),
	}
	
	// Setup test environment
	suite.testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{"../../config/crd/bases"},
		ErrorIfCRDPathMissing: false,
	}
	
	cfg, err := suite.testEnv.Start()
	if err != nil {
		b.Fatalf("Failed to start test environment: %v", err)
	}
	
	suite.cfg = cfg
	
	// Create Kubernetes client
	scheme := ctrl.GetConfigOrDie().Scheme
	err = n8nv1alpha1.AddToScheme(scheme)
	if err != nil {
		b.Fatalf("Failed to add scheme: %v", err)
	}
	
	suite.k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		b.Fatalf("Failed to create client: %v", err)
	}
	
	suite.clientset, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		b.Fatalf("Failed to create clientset: %v", err)
	}
	
	return suite
}

// teardownBenchmark cleans up the benchmark environment
func (suite *BenchmarkSuite) teardownBenchmark(b *testing.B) {
	if suite.testEnv != nil {
		err := suite.testEnv.Stop()
		if err != nil {
			b.Logf("Failed to stop test environment: %v", err)
		}
	}
}

// BenchmarkN8nInstanceCreate benchmarks N8nInstance creation
func BenchmarkN8nInstanceCreate(b *testing.B) {
	suite := setupBenchmark(b)
	defer suite.teardownBenchmark(b)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		instance := &n8nv1alpha1.N8nInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("bench-create-%d", i),
				Namespace: suite.namespace,
			},
			Spec: n8nv1alpha1.N8nInstanceSpec{
				Version: "1.0.0",
				Domain:  fmt.Sprintf("bench-%d.test.local", i),
				Components: &n8nv1alpha1.ComponentsSpec{
					Main: &n8nv1alpha1.ComponentSpec{
						Replicas: 1,
						Port:     5678,
					},
				},
			},
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := suite.k8sClient.Create(ctx, instance)
		cancel()
		
		if err != nil {
			b.Errorf("Failed to create instance: %v", err)
		}
	}
}

// BenchmarkN8nInstanceUpdate benchmarks N8nInstance updates
func BenchmarkN8nInstanceUpdate(b *testing.B) {
	suite := setupBenchmark(b)
	defer suite.teardownBenchmark(b)
	
	// Create base instance
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bench-update",
			Namespace: suite.namespace,
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  "bench-update.test.local",
			Components: &n8nv1alpha1.ComponentsSpec{
				Main: &n8nv1alpha1.ComponentSpec{
					Replicas: 1,
					Port:     5678,
				},
			},
		},
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := suite.k8sClient.Create(ctx, instance)
	cancel()
	if err != nil {
		b.Fatalf("Failed to create base instance: %v", err)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		
		// Get latest version
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		}, instance)
		if err != nil {
			cancel()
			b.Errorf("Failed to get instance: %v", err)
			continue
		}
		
		// Update instance
		if instance.Labels == nil {
			instance.Labels = make(map[string]string)
		}
		instance.Labels["benchmark"] = fmt.Sprintf("%d", i)
		
		err = suite.k8sClient.Update(ctx, instance)
		cancel()
		
		if err != nil {
			b.Errorf("Failed to update instance: %v", err)
		}
	}
}

// BenchmarkN8nInstanceGet benchmarks N8nInstance retrieval
func BenchmarkN8nInstanceGet(b *testing.B) {
	suite := setupBenchmark(b)
	defer suite.teardownBenchmark(b)
	
	// Create base instance
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bench-get",
			Namespace: suite.namespace,
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  "bench-get.test.local",
			Components: &n8nv1alpha1.ComponentsSpec{
				Main: &n8nv1alpha1.ComponentSpec{
					Replicas: 1,
					Port:     5678,
				},
			},
		},
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := suite.k8sClient.Create(ctx, instance)
	cancel()
	if err != nil {
		b.Fatalf("Failed to create base instance: %v", err)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
		retrievedInstance := &n8nv1alpha1.N8nInstance{}
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		}, retrievedInstance)
		cancel()
		
		if err != nil {
			b.Errorf("Failed to get instance: %v", err)
		}
	}
}

// BenchmarkN8nInstanceList benchmarks N8nInstance listing
func BenchmarkN8nInstanceList(b *testing.B) {
	suite := setupBenchmark(b)
	defer suite.teardownBenchmark(b)
	
	// Create multiple instances
	instanceCount := 10
	for i := 0; i < instanceCount; i++ {
		instance := &n8nv1alpha1.N8nInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("bench-list-%d", i),
				Namespace: suite.namespace,
			},
			Spec: n8nv1alpha1.N8nInstanceSpec{
				Version: "1.0.0",
				Domain:  fmt.Sprintf("bench-list-%d.test.local", i),
				Components: &n8nv1alpha1.ComponentsSpec{
					Main: &n8nv1alpha1.ComponentSpec{
						Replicas: 1,
						Port:     5678,
					},
				},
			},
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := suite.k8sClient.Create(ctx, instance)
		cancel()
		if err != nil {
			b.Fatalf("Failed to create instance %d: %v", i, err)
		}
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
		instanceList := &n8nv1alpha1.N8nInstanceList{}
		err := suite.k8sClient.List(ctx, instanceList, client.InNamespace(suite.namespace))
		cancel()
		
		if err != nil {
			b.Errorf("Failed to list instances: %v", err)
		}
		
		if len(instanceList.Items) != instanceCount {
			b.Errorf("Expected %d instances, got %d", instanceCount, len(instanceList.Items))
		}
	}
}

// BenchmarkN8nInstanceDelete benchmarks N8nInstance deletion
func BenchmarkN8nInstanceDelete(b *testing.B) {
	suite := setupBenchmark(b)
	defer suite.teardownBenchmark(b)
	
	// Pre-create instances for deletion
	instances := make([]*n8nv1alpha1.N8nInstance, b.N)
	for i := 0; i < b.N; i++ {
		instance := &n8nv1alpha1.N8nInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("bench-delete-%d", i),
				Namespace: suite.namespace,
			},
			Spec: n8nv1alpha1.N8nInstanceSpec{
				Version: "1.0.0",
				Domain:  fmt.Sprintf("bench-delete-%d.test.local", i),
				Components: &n8nv1alpha1.ComponentsSpec{
					Main: &n8nv1alpha1.ComponentSpec{
						Replicas: 1,
						Port:     5678,
					},
				},
			},
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := suite.k8sClient.Create(ctx, instance)
		cancel()
		if err != nil {
			b.Fatalf("Failed to create instance %d: %v", i, err)
		}
		
		instances[i] = instance
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := suite.k8sClient.Delete(ctx, instances[i])
		cancel()
		
		if err != nil {
			b.Errorf("Failed to delete instance: %v", err)
		}
	}
}

// BenchmarkConcurrentOperations benchmarks concurrent operations
func BenchmarkConcurrentOperations(b *testing.B) {
	suite := setupBenchmark(b)
	defer suite.teardownBenchmark(b)
	
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			instance := &n8nv1alpha1.N8nInstance{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("bench-concurrent-%d-%d", b.N, counter),
					Namespace: suite.namespace,
				},
				Spec: n8nv1alpha1.N8nInstanceSpec{
					Version: "1.0.0",
					Domain:  fmt.Sprintf("bench-concurrent-%d-%d.test.local", b.N, counter),
					Components: &n8nv1alpha1.ComponentsSpec{
						Main: &n8nv1alpha1.ComponentSpec{
							Replicas: 1,
							Port:     5678,
						},
					},
				},
			}
			
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := suite.k8sClient.Create(ctx, instance)
			cancel()
			
			if err != nil {
				b.Errorf("Failed to create instance: %v", err)
			}
			
			counter++
		}
	})
}

// BenchmarkValidationWebhook benchmarks validation webhook performance
func BenchmarkValidationWebhook(b *testing.B) {
	suite := setupBenchmark(b)
	defer suite.teardownBenchmark(b)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Create instance with various validation scenarios
		instance := &n8nv1alpha1.N8nInstance{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("bench-validation-%d", i),
				Namespace: suite.namespace,
			},
			Spec: n8nv1alpha1.N8nInstanceSpec{
				Version: "1.0.0",
				Domain:  fmt.Sprintf("bench-validation-%d.test.local", i),
				Components: &n8nv1alpha1.ComponentsSpec{
					Main: &n8nv1alpha1.ComponentSpec{
						Replicas: 1,
						Port:     5678,
						Resources: &n8nv1alpha1.ResourcesSpec{
							Requests: &n8nv1alpha1.ResourceRequirementsSpec{
								CPU:    "100m",
								Memory: "128Mi",
							},
							Limits: &n8nv1alpha1.ResourceRequirementsSpec{
								CPU:    "500m",
								Memory: "512Mi",
							},
						},
					},
					Webhook: &n8nv1alpha1.ComponentSpec{
						Replicas: 1,
						Port:     5679,
					},
					Worker: &n8nv1alpha1.ComponentSpec{
						Replicas: 2,
					},
				},
				Storage: &n8nv1alpha1.StorageSpec{
					Persistent: &n8nv1alpha1.PersistentStorageSpec{
						Type:         "ebs-csi",
						StorageClass: "gp3",
						Size:         "10Gi",
					},
				},
			},
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := suite.k8sClient.Create(ctx, instance)
		cancel()
		
		if err != nil {
			b.Errorf("Failed to create instance with validation: %v", err)
		}
	}
}

// BenchmarkStatusUpdate benchmarks status updates
func BenchmarkStatusUpdate(b *testing.B) {
	suite := setupBenchmark(b)
	defer suite.teardownBenchmark(b)
	
	// Create base instance
	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bench-status",
			Namespace: suite.namespace,
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Version: "1.0.0",
			Domain:  "bench-status.test.local",
			Components: &n8nv1alpha1.ComponentsSpec{
				Main: &n8nv1alpha1.ComponentSpec{
					Replicas: 1,
					Port:     5678,
				},
			},
		},
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := suite.k8sClient.Create(ctx, instance)
	cancel()
	if err != nil {
		b.Fatalf("Failed to create base instance: %v", err)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		
		// Get latest version
		err := suite.k8sClient.Get(ctx, types.NamespacedName{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		}, instance)
		if err != nil {
			cancel()
			b.Errorf("Failed to get instance: %v", err)
			continue
		}
		
		// Update status
		instance.Status.Phase = n8nv1alpha1.N8nInstancePhaseProgressing
		instance.Status.ObservedGeneration = instance.Generation
		instance.Status.Conditions = []n8nv1alpha1.N8nInstanceCondition{
			{
				Type:               n8nv1alpha1.ConditionTypeProgressing,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             "Reconciling",
				Message:            fmt.Sprintf("Benchmark update %d", i),
			},
		}
		
		err = suite.k8sClient.Status().Update(ctx, instance)
		cancel()
		
		if err != nil {
			b.Errorf("Failed to update status: %v", err)
		}
	}
}
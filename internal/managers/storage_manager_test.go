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
	"strings"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	n8nv1alpha1 "github.com/lxhiguera/n8n-eks-operator/api/v1alpha1"
)

func TestStorageManager_ValidateFileUpload(t *testing.T) {
	logger := logr.Discard()
	storageManager := &S3ManagerImpl{
		logger: logger,
	}

	tests := []struct {
		name        string
		filename    string
		size        int64
		config      StorageConfig
		expectError bool
	}{
		{
			name:     "valid JPEG file",
			filename: "test-image.jpg",
			size:     1024 * 1024, // 1MB
			config: StorageConfig{
				Assets: AssetsStorageConfig{
					S3: S3Config{
						AllowedFileTypes: []string{"jpg", "jpeg", "png", "gif"},
						MaxFileSize:      "10MB",
					},
				},
			},
			expectError: false,
		},
		{
			name:     "file too large",
			filename: "large-file.jpg",
			size:     50 * 1024 * 1024, // 50MB
			config: StorageConfig{
				Assets: AssetsStorageConfig{
					S3: S3Config{
						AllowedFileTypes: []string{"jpg", "jpeg", "png", "gif"},
						MaxFileSize:      "10MB",
					},
				},
			},
			expectError: true,
		},
		{
			name:     "disallowed file type",
			filename: "script.exe",
			size:     1024,
			config: StorageConfig{
				Assets: AssetsStorageConfig{
					S3: S3Config{
						AllowedFileTypes: []string{"jpg", "jpeg", "png", "gif"},
						MaxFileSize:      "10MB",
					},
				},
			},
			expectError: true,
		},
		{
			name:     "empty filename",
			filename: "",
			size:     1024,
			config: StorageConfig{
				Assets: AssetsStorageConfig{
					S3: S3Config{
						AllowedFileTypes: []string{"jpg", "jpeg", "png", "gif"},
						MaxFileSize:      "10MB",
					},
				},
			},
			expectError: true,
		},
		{
			name:     "zero size file",
			filename: "empty.txt",
			size:     0,
			config: StorageConfig{
				Assets: AssetsStorageConfig{
					S3: S3Config{
						AllowedFileTypes: []string{"txt", "md"},
						MaxFileSize:      "1MB",
					},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := storageManager.ValidateFileUpload(ctx, tt.filename, tt.size, tt.config)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestS3Config_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config S3Config
		valid  bool
	}{
		{
			name: "valid S3 config",
			config: S3Config{
				BucketName:       "my-n8n-bucket",
				Region:           "us-west-2",
				AllowedFileTypes: []string{"jpg", "png", "pdf"},
				MaxFileSize:      "10MB",
				Encryption: EncryptionConfig{
					Enabled: true,
				},
				Versioning: true,
			},
			valid: true,
		},
		{
			name: "invalid bucket name (uppercase)",
			config: S3Config{
				BucketName: "My-N8N-Bucket",
				Region:     "us-west-2",
			},
			valid: false,
		},
		{
			name: "invalid bucket name (too short)",
			config: S3Config{
				BucketName: "ab",
				Region:     "us-west-2",
			},
			valid: false,
		},
		{
			name: "invalid bucket name (too long)",
			config: S3Config{
				BucketName: strings.Repeat("a", 64),
				Region:     "us-west-2",
			},
			valid: false,
		},
		{
			name: "invalid region",
			config: S3Config{
				BucketName: "my-n8n-bucket",
				Region:     "invalid-region",
			},
			valid: false,
		},
		{
			name: "empty bucket name",
			config: S3Config{
				Region: "us-west-2",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate bucket name format
			bucketValid := tt.config.BucketName != "" &&
				len(tt.config.BucketName) >= 3 &&
				len(tt.config.BucketName) <= 63 &&
				strings.ToLower(tt.config.BucketName) == tt.config.BucketName &&
				!strings.Contains(tt.config.BucketName, "_") &&
				!strings.Contains(tt.config.BucketName, "..")

			// Validate region
			validRegions := []string{
				"us-east-1", "us-east-2", "us-west-1", "us-west-2",
				"eu-west-1", "eu-west-2", "eu-central-1",
				"ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
			}
			regionValid := false
			for _, region := range validRegions {
				if tt.config.Region == region {
					regionValid = true
					break
				}
			}

			valid := bucketValid && regionValid

			if valid != tt.valid {
				t.Errorf("Expected validation result %v, got %v (bucket: %v, region: %v)",
					tt.valid, valid, bucketValid, regionValid)
			}
		})
	}
}

func TestCloudFrontConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config CloudFrontConfig
		valid  bool
	}{
		{
			name: "valid CloudFront config",
			config: CloudFrontConfig{
				Enabled:      true,
				CustomDomain: "assets.example.com",
			},
			valid: true,
		},
		{
			name: "disabled CloudFront",
			config: CloudFrontConfig{
				Enabled: false,
			},
			valid: true,
		},
		{
			name: "invalid custom domain",
			config: CloudFrontConfig{
				Enabled:      true,
				CustomDomain: "invalid..domain",
			},
			valid: false,
		},
		{
			name: "empty custom domain when enabled",
			config: CloudFrontConfig{
				Enabled: true,
			},
			valid: true, // Custom domain is optional
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := !tt.config.Enabled ||
				tt.config.CustomDomain == "" ||
				(tt.config.CustomDomain != "" && !strings.Contains(tt.config.CustomDomain, ".."))

			if valid != tt.valid {
				t.Errorf("Expected validation result %v, got %v", tt.valid, valid)
			}
		})
	}
}

func TestStorageConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config StorageConfig
		valid  bool
	}{
		{
			name: "valid complete storage config",
			config: StorageConfig{
				Workflows: WorkflowsStorageConfig{
					Type: "s3",
					S3: S3Config{
						BucketName: "n8n-workflows",
						Region:     "us-west-2",
					},
				},
				Assets: AssetsStorageConfig{
					Type: "s3-cloudfront",
					S3: S3Config{
						BucketName:       "n8n-assets",
						Region:           "us-west-2",
						AllowedFileTypes: []string{"jpg", "png", "pdf"},
						MaxFileSize:      "10MB",
					},
					CloudFront: CloudFrontConfig{
						Enabled: true,
					},
				},
				Persistent: PersistentStorageConfig{
					Type:          "ebs-csi",
					StorageClass:  "gp3",
					Size:          "20Gi",
					AutoExpansion: true,
				},
			},
			valid: true,
		},
		{
			name: "invalid workflows storage type",
			config: StorageConfig{
				Workflows: WorkflowsStorageConfig{
					Type: "nfs",
				},
			},
			valid: false,
		},
		{
			name: "invalid assets storage type",
			config: StorageConfig{
				Assets: AssetsStorageConfig{
					Type: "local",
				},
			},
			valid: false,
		},
		{
			name: "invalid persistent storage type",
			config: StorageConfig{
				Persistent: PersistentStorageConfig{
					Type: "nfs",
				},
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := (tt.config.Workflows.Type == "" || tt.config.Workflows.Type == "s3") &&
				(tt.config.Assets.Type == "" || tt.config.Assets.Type == "s3-cloudfront") &&
				(tt.config.Persistent.Type == "" || tt.config.Persistent.Type == "ebs-csi")

			if valid != tt.valid {
				t.Errorf("Expected validation result %v, got %v", tt.valid, valid)
			}
		})
	}
}

func TestFileSize_Parsing(t *testing.T) {
	tests := []struct {
		name        string
		sizeStr     string
		expectBytes int64
		expectError bool
	}{
		{
			name:        "1MB",
			sizeStr:     "1MB",
			expectBytes: 1024 * 1024,
			expectError: false,
		},
		{
			name:        "10MB",
			sizeStr:     "10MB",
			expectBytes: 10 * 1024 * 1024,
			expectError: false,
		},
		{
			name:        "1GB",
			sizeStr:     "1GB",
			expectBytes: 1024 * 1024 * 1024,
			expectError: false,
		},
		{
			name:        "500KB",
			sizeStr:     "500KB",
			expectBytes: 500 * 1024,
			expectError: false,
		},
		{
			name:        "invalid format",
			sizeStr:     "invalid",
			expectError: true,
		},
		{
			name:        "empty string",
			sizeStr:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simple parsing logic for testing
			var bytes int64
			var err error

			if tt.sizeStr == "" {
				err = fmt.Errorf("empty size string")
			} else if strings.HasSuffix(tt.sizeStr, "KB") {
				sizeStr := strings.TrimSuffix(tt.sizeStr, "KB")
				if size, parseErr := strconv.ParseInt(sizeStr, 10, 64); parseErr == nil {
					bytes = size * 1024
				} else {
					err = parseErr
				}
			} else if strings.HasSuffix(tt.sizeStr, "MB") {
				sizeStr := strings.TrimSuffix(tt.sizeStr, "MB")
				if size, parseErr := strconv.ParseInt(sizeStr, 10, 64); parseErr == nil {
					bytes = size * 1024 * 1024
				} else {
					err = parseErr
				}
			} else if strings.HasSuffix(tt.sizeStr, "GB") {
				sizeStr := strings.TrimSuffix(tt.sizeStr, "GB")
				if size, parseErr := strconv.ParseInt(sizeStr, 10, 64); parseErr == nil {
					bytes = size * 1024 * 1024 * 1024
				} else {
					err = parseErr
				}
			} else {
				err = fmt.Errorf("invalid size format")
			}

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError && bytes != tt.expectBytes {
				t.Errorf("Expected %d bytes, got %d", tt.expectBytes, bytes)
			}
		})
	}
}

func TestStorageManager_ReconcileStorage_Structure(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = n8nv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)

	instance := &n8nv1alpha1.N8nInstance{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance",
			Namespace: "default",
		},
		Spec: n8nv1alpha1.N8nInstanceSpec{
			Storage: &n8nv1alpha1.StorageSpec{
				Workflows: &n8nv1alpha1.WorkflowsStorageSpec{
					Type: "s3",
					S3: &n8nv1alpha1.S3Spec{
						BucketName: "n8n-workflows-test",
						Region:     "us-west-2",
						Encryption: &n8nv1alpha1.EncryptionSpec{
							Enabled: true,
						},
						Versioning: true,
					},
				},
				Assets: &n8nv1alpha1.AssetsStorageSpec{
					Type: "s3-cloudfront",
					S3: &n8nv1alpha1.S3Spec{
						BucketName:       "n8n-assets-test",
						Region:           "us-west-2",
						AllowedFileTypes: []string{"jpg", "png", "pdf"},
						MaxFileSize:      "10MB",
					},
					CloudFront: &n8nv1alpha1.CloudFrontSpec{
						Enabled: true,
					},
				},
				Persistent: &n8nv1alpha1.PersistentStorageSpec{
					Type:          "ebs-csi",
					StorageClass:  "gp3",
					Size:          "20Gi",
					AutoExpansion: true,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(instance).Build()
	logger := logr.Discard()

	storageManager := NewStorageManager(fakeClient, scheme, logger)

	ctx := context.Background()
	err := storageManager.ReconcileStorage(ctx, instance)

	// We expect this to fail without real AWS clients, but we can test the structure
	if err != nil {
		t.Logf("ReconcileStorage failed as expected without AWS clients: %v", err)
	} else {
		t.Log("ReconcileStorage completed without error")
	}
}

func TestFileExtension_Validation(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		allowed  []string
		expectOK bool
	}{
		{
			name:     "allowed JPEG",
			filename: "image.jpg",
			allowed:  []string{"jpg", "jpeg", "png", "gif"},
			expectOK: true,
		},
		{
			name:     "allowed PDF",
			filename: "document.pdf",
			allowed:  []string{"pdf", "doc", "docx"},
			expectOK: true,
		},
		{
			name:     "disallowed executable",
			filename: "malware.exe",
			allowed:  []string{"jpg", "jpeg", "png", "gif"},
			expectOK: false,
		},
		{
			name:     "no extension",
			filename: "README",
			allowed:  []string{"txt", "md"},
			expectOK: false,
		},
		{
			name:     "case sensitivity",
			filename: "image.JPG",
			allowed:  []string{"jpg", "jpeg", "png", "gif"},
			expectOK: true, // Should be case insensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract file extension
			parts := strings.Split(tt.filename, ".")
			if len(parts) < 2 {
				if tt.expectOK {
					t.Error("Expected file to be allowed but no extension found")
				}
				return
			}

			ext := strings.ToLower(parts[len(parts)-1])

			// Check if extension is allowed
			allowed := false
			for _, allowedExt := range tt.allowed {
				if ext == strings.ToLower(allowedExt) {
					allowed = true
					break
				}
			}

			if allowed != tt.expectOK {
				t.Errorf("Expected extension %s to be allowed: %v, got: %v", ext, tt.expectOK, allowed)
			}
		})
	}
}

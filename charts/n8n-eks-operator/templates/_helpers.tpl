{{/*
Expand the name of the chart.
*/}}
{{- define "n8n-eks-operator.name" -}}
{{- default .Chart.Name .Values.operator.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "n8n-eks-operator.fullname" -}}
{{- if .Values.operator.fullnameOverride }}
{{- .Values.operator.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.operator.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "n8n-eks-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "n8n-eks-operator.labels" -}}
helm.sh/chart: {{ include "n8n-eks-operator.chart" . }}
{{ include "n8n-eks-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.global.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "n8n-eks-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "n8n-eks-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "n8n-eks-operator.serviceAccountName" -}}
{{- if .Values.operator.serviceAccount.create }}
{{- default (include "n8n-eks-operator.fullname" .) .Values.operator.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.operator.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the webhook certificate secret
*/}}
{{- define "n8n-eks-operator.webhookCertSecretName" -}}
{{- if .Values.webhook.certificate.custom.enabled }}
{{- .Values.webhook.certificate.custom.secretName }}
{{- else }}
{{- printf "%s-webhook-server-cert" (include "n8n-eks-operator.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Generate webhook certificate
*/}}
{{- define "n8n-eks-operator.webhookCert" -}}
{{- $altNames := list ( printf "%s-webhook-service.%s.svc" (include "n8n-eks-operator.fullname" .) .Release.Namespace ) ( printf "%s-webhook-service.%s.svc.cluster.local" (include "n8n-eks-operator.fullname" .) .Release.Namespace ) -}}
{{- $ca := genCA "n8n-eks-operator-ca" 365 -}}
{{- $cert := genSignedCert ( include "n8n-eks-operator.fullname" . ) nil $altNames 365 $ca -}}
{{- $cert.Cert -}}
{{- end }}

{{/*
Generate webhook private key
*/}}
{{- define "n8n-eks-operator.webhookKey" -}}
{{- $altNames := list ( printf "%s-webhook-service.%s.svc" (include "n8n-eks-operator.fullname" .) .Release.Namespace ) ( printf "%s-webhook-service.%s.svc.cluster.local" (include "n8n-eks-operator.fullname" .) .Release.Namespace ) -}}
{{- $ca := genCA "n8n-eks-operator-ca" 365 -}}
{{- $cert := genSignedCert ( include "n8n-eks-operator.fullname" . ) nil $altNames 365 $ca -}}
{{- $cert.Key -}}
{{- end }}

{{/*
Generate webhook CA bundle
*/}}
{{- define "n8n-eks-operator.webhookCABundle" -}}
{{- $ca := genCA "n8n-eks-operator-ca" 365 -}}
{{- $ca.Cert | b64enc -}}
{{- end }}

{{/*
Create default N8nInstance configuration
*/}}
{{- define "n8n-eks-operator.defaultN8nInstanceConfig" -}}
{{- with .Values.defaultN8nInstance }}
version: {{ .version | quote }}
components:
  main:
    replicas: {{ .components.main.replicas }}
    resources:
      requests:
        cpu: {{ .components.main.resources.requests.cpu | quote }}
        memory: {{ .components.main.resources.requests.memory | quote }}
      limits:
        cpu: {{ .components.main.resources.limits.cpu | quote }}
        memory: {{ .components.main.resources.limits.memory | quote }}
  webhook:
    replicas: {{ .components.webhook.replicas }}
    resources:
      requests:
        cpu: {{ .components.webhook.resources.requests.cpu | quote }}
        memory: {{ .components.webhook.resources.requests.memory | quote }}
      limits:
        cpu: {{ .components.webhook.resources.limits.cpu | quote }}
        memory: {{ .components.webhook.resources.limits.memory | quote }}
  worker:
    replicas: {{ .components.worker.replicas }}
    resources:
      requests:
        cpu: {{ .components.worker.resources.requests.cpu | quote }}
        memory: {{ .components.worker.resources.requests.memory | quote }}
      limits:
        cpu: {{ .components.worker.resources.limits.cpu | quote }}
        memory: {{ .components.worker.resources.limits.memory | quote }}
storage:
  persistent:
    storageClass: {{ .storage.persistent.storageClass | quote }}
    size: {{ .storage.persistent.size | quote }}
    autoExpansion: {{ .storage.persistent.autoExpansion }}
monitoring:
  metrics:
    enabled: {{ .monitoring.metrics.enabled }}
  logging:
    level: {{ .monitoring.logging.level | quote }}
security:
  podSecurityStandard: {{ .security.podSecurityStandard | quote }}
  networkPolicies:
    enabled: {{ .security.networkPolicies.enabled }}
{{- end }}
{{- end }}

{{/*
Validate configuration
*/}}
{{- define "n8n-eks-operator.validateConfig" -}}
{{- if and .Values.webhook.enabled (not .Values.webhook.certificate.certManager.enabled) (not .Values.webhook.certificate.custom.enabled) (not .Values.webhook.certificate.selfSigned.enabled) }}
{{- fail "When webhook is enabled, at least one certificate method must be enabled (certManager, custom, or selfSigned)" }}
{{- end }}
{{- if and .Values.webhook.certificate.certManager.enabled (not .Values.webhook.certificate.certManager.issuer) (not .Values.webhook.certificate.certManager.issuerRef) }}
{{- fail "When cert-manager is enabled for webhooks, either issuer or issuerRef must be specified" }}
{{- end }}
{{- if and .Values.webhook.certificate.custom.enabled (not .Values.webhook.certificate.custom.secretName) }}
{{- fail "When custom certificate is enabled for webhooks, secretName must be specified" }}
{{- end }}
{{- if and .Values.operator.autoscaling.enabled (lt (.Values.operator.autoscaling.minReplicas | int) 1) }}
{{- fail "When autoscaling is enabled, minReplicas must be at least 1" }}
{{- end }}
{{- if and .Values.operator.autoscaling.enabled (gt (.Values.operator.autoscaling.minReplicas | int) (.Values.operator.autoscaling.maxReplicas | int)) }}
{{- fail "When autoscaling is enabled, minReplicas must be less than or equal to maxReplicas" }}
{{- end }}
{{- if and .Values.operator.podDisruptionBudget.enabled .Values.operator.podDisruptionBudget.minAvailable .Values.operator.podDisruptionBudget.maxUnavailable }}
{{- fail "PodDisruptionBudget cannot have both minAvailable and maxUnavailable set" }}
{{- end }}
{{- end }}

{{/*
Generate AWS tags
*/}}
{{- define "n8n-eks-operator.awsTags" -}}
{{- $tags := dict }}
{{- $tags = merge $tags .Values.aws.defaultTags }}
{{- $tags = merge $tags (dict "kubernetes.io/cluster" .Values.aws.cluster.name) }}
{{- $tags = merge $tags (dict "kubernetes.io/namespace" .Release.Namespace) }}
{{- $tags = merge $tags (dict "app.kubernetes.io/name" (include "n8n-eks-operator.name" .)) }}
{{- $tags = merge $tags (dict "app.kubernetes.io/instance" .Release.Name) }}
{{- $tags = merge $tags (dict "app.kubernetes.io/managed-by" "n8n-eks-operator") }}
{{- toYaml $tags }}
{{- end }}

{{/*
Generate Pod Security Standards labels for namespace
*/}}
{{- define "n8n-eks-operator.podSecurityLabels" -}}
{{- if .Values.podSecurityStandards.enforce }}
pod-security.kubernetes.io/enforce: {{ .Values.podSecurityStandards.enforce | quote }}
{{- end }}
{{- if .Values.podSecurityStandards.audit }}
pod-security.kubernetes.io/audit: {{ .Values.podSecurityStandards.audit | quote }}
{{- end }}
{{- if .Values.podSecurityStandards.warn }}
pod-security.kubernetes.io/warn: {{ .Values.podSecurityStandards.warn | quote }}
{{- end }}
{{- end }}

{{/*
Generate resource requirements
*/}}
{{- define "n8n-eks-operator.resources" -}}
{{- if .Values.operator.resources }}
resources:
  {{- if .Values.operator.resources.limits }}
  limits:
    {{- if .Values.operator.resources.limits.cpu }}
    cpu: {{ .Values.operator.resources.limits.cpu | quote }}
    {{- end }}
    {{- if .Values.operator.resources.limits.memory }}
    memory: {{ .Values.operator.resources.limits.memory | quote }}
    {{- end }}
  {{- end }}
  {{- if .Values.operator.resources.requests }}
  requests:
    {{- if .Values.operator.resources.requests.cpu }}
    cpu: {{ .Values.operator.resources.requests.cpu | quote }}
    {{- end }}
    {{- if .Values.operator.resources.requests.memory }}
    memory: {{ .Values.operator.resources.requests.memory | quote }}
    {{- end }}
  {{- end }}
{{- end }}
{{- end }}

{{/*
Call validation
*/}}
{{- include "n8n-eks-operator.validateConfig" . }}
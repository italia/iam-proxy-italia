{{/*
Expand the name of the chart.
*/}}
{{- define "iam-proxy-italia.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "iam-proxy-italia.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
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
{{- define "iam-proxy-italia.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "iam-proxy-italia.labels" -}}
helm.sh/chart: {{ include "iam-proxy-italia.chart" . }}
{{ include "iam-proxy-italia.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "iam-proxy-italia.selectorLabels" -}}
app.kubernetes.io/name: {{ include "iam-proxy-italia.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "iam-proxy-italia.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "iam-proxy-italia.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the secret to use
*/}}
{{- define "iam-proxy-italia.secret" -}}
{{- if .Values.secret.existingSecret }}
{{- .Values.secret.existingSecret }}
{{- else }}
{{- default (include "iam-proxy-italia.fullname" .) .Values.secret.name }}
{{- end }}
{{- end }}

{{/*
Fully qualified name for the static-files deployment and service.
*/}}
{{- define "iam-proxy-italia.staticFullname" -}}
{{- printf "%s-static" (include "iam-proxy-italia.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Selector labels for the static-files deployment (distinct from the main app selectors).
*/}}
{{- define "iam-proxy-italia.staticSelectorLabels" -}}
app.kubernetes.io/name: {{ printf "%s-static" (include "iam-proxy-italia.name" .) }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

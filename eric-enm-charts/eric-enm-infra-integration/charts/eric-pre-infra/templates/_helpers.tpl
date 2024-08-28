{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "eric-pre-infra.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "eric-pre-infra.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- printf .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-pre-infra.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create image registry url
*/}}
{{- define "eric-pre-infra.registryUrl" -}}
{{- if .Values.global.registry.url -}}
{{- print .Values.global.registry.url -}}
{{- else -}}
{{- print .Values.imageCredentials.registry.url -}}
{{- end -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "eric-pre-infra.pullSecrets" -}}
{{- if .Values.global.pullSecret -}}
{{- print .Values.global.pullSecret -}}
{{- else if .Values.imageCredentials.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Create replicas
*/}}
{{- define "eric-pre-infra.replicas" -}}
{{- if index .Values "global" "replicas-eric-pre-infra" -}}
{{- print (index .Values "global" "replicas-eric-pre-infra") -}}
{{- else if index .Values "replicas-eric-pre-infra" -}}
{{- print (index .Values "replicas-eric-pre-infra") -}}
{{- end -}}
{{- end -}}

{{/*
Create Storage Class
*/}}
{{- define "eric-pre-infra.storageClass" -}}
{{- if .Values.global.persistentVolumeClaim.storageClass -}}
{{- print .Values.global.persistentVolumeClaim.storageClass -}}
{{- else if .Values.persistentVolumeClaim.storageClass -}}
{{- print .Values.persistentVolumeClaim.storageClass -}}
{{- end -}}
{{- end -}}

{{/*
Generate chart secret name
*/}}
{{- define "eric-pre-infra.secretName" -}}
{{ default (include "eric-pre-infra.fullname" .) .Values.existingSecret }}
{{- end -}}

Generate Product info
*/}}
{{- define "eric-pre-infra.product-info" }}
ericsson.com/product-name: "helm-eric-pre-infra"
ericsson.com/product-number: "CXC 174 3150"
ericsson.com/product-revision: "{{.Values.productRevision}}"
{{- end}}

{{/*
Set IANA Timezone
DR-HC-146 requires setting a default TZ of UTC if the optional
global .Values.global.timezone and local .Values.timezone values are not set.
Unlike many other DRs, the global timezone value must override a local value.
*/}}
{{- define "eric-pre-infra.timezone" -}}
{{- if .Values.global.enmProperties.timezone -}}
{{- print .Values.global.enmProperties.timezone -}}
{{- else if .Values.timezone -}}
{{- print .Values.timezone -}}
{{- else -}}
UTC
{{- end -}}
{{- end -}}

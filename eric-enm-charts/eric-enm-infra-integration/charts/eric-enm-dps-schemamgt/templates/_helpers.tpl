{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "eric-enm-dps-schemamgt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Chart version.
*/}}
{{- define "{{.Chart.Name}}.version" -}}
{{- printf "%s" .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "{{.Chart.Name}}.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "{{.Chart.Name}}.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "eric-enm-dps-schemamgt.fullname" -}}
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
{{- define "eric-enm-dps-schemamgt.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create image registry url
*/}}
{{- define "eric-enm-dps-schemamgt.registryUrl" -}}
{{- if .Values.global.registry.url -}}
{{- print .Values.global.registry.url -}}
{{- else -}}
{{- print .Values.imageCredentials.registry.url -}}
{{- end -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "eric-enm-dps-schemamgt.pullSecrets" -}}
{{- if .Values.global.pullSecret -}}
{{- print .Values.global.pullSecret -}}
{{- else if .Values.imageCredentials.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Create a default fully qualified app name for secrets.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "{{.Chart.Name}}.secrets.name" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-secrets" $name | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create replicas
*/}}
{{- define "eric-enm-dps-schemamgt.replicas" -}}
{{- if index .Values "global" "replicas-eric-enm-dps-schemamgt" -}}
{{- print (index .Values "global" "replicas-eric-enm-dps-schemamgt") -}}
{{- else if index .Values "replicas-eric-enm-dps-schemamgt" -}}
{{- print (index .Values "replicas-eric-enm-dps-schemamgt") -}}
{{- end -}}
{{- end -}}

{{/*
Create Storage Class
*/}}
{{- define "eric-enm-dps-schemamgt.storageClass" -}}
{{- if .Values.global.persistentVolumeClaim.storageClass -}}
{{- print .Values.global.persistentVolumeClaim.storageClass -}}
{{- else if .Values.persistentVolumeClaim.storageClass -}}
{{- print .Values.persistentVolumeClaim.storageClass -}}
{{- end -}}
{{- end -}}

{{/*
Generate Product info
*/}}
{{- define "eric-enm-dps-schemamgt.product-info" }}
ericsson.com/product-name: "eric-enm-dps-schemamgt"
ericsson.com/product-number: "CXU_Placeholder"
ericsson.com/product-revision: "{{.Values.productRevision}}"
{{- end}}



{{/*
Generate chart secret name
*/}}
{{- define "eric-enm-dps-schemamgt.secretName" -}}
{{ default (include "eric-enm-dps-schemamgt.fullname" .) .Values.existingSecret }}
{{- end -}}

{{/*
Set IANA Timezone
DR-HC-146 requires setting a default TZ of UTC if the optional
global .Values.global.timezone and local .Values.timezone values are not set.
Unlike many other DRs, the global timezone value must override a local value.
*/}}
{{- define "eric-enm-dps-schemamgt.timezone" -}}
{{- if .Values.global.enmProperties.timezone -}}
{{- print .Values.global.enmProperties.timezone -}}
{{- else if .Values.timezone -}}
{{- print .Values.timezone -}}
{{- else -}}
UTC
{{- end -}}
{{- end -}}

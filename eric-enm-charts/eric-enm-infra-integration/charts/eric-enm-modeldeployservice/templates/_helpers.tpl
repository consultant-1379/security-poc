{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "eric-enm-modeldeployservice.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "eric-enm-modeldeployservice.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-enm-modeldeployservice.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Generate product name
*/}}
{{- define "eric-enm-modeldeployservice.productName" -}}
{{- $product_name := printf "%s-%s" "helm" .Chart.Name -}}
{{- print $product_name -}}
{{- end -}}

{{/*
Generate Product info
*/}}
{{- define "eric-enm-modeldeployservice.product-info" }}
ericsson.com/product-name: {{ include "eric-enm-modeldeployservice.productName" . }}
ericsson.com/product-number: {{ .Values.productNumber }}
ericsson.com/product-revision: {{regexReplaceAll "(.*)[+|-].*" .Chart.Version "${1}" }}
{{- end}}

{{/*
Common labels
*/}}
{{- define "eric-enm-modeldeployservice.labels" -}}
app.kubernetes.io/name: {{ include "eric-enm-modeldeployservice.name" . }}
helm.sh/chart: {{ include "eric-enm-modeldeployservice.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Values.labels }}
{{ toYaml .Values.labels }}
{{- end }}
{{- end -}}

{{/*
Create image registry url
*/}}
{{- define "eric-enm-modeldeployservice.registryUrl" -}}
{{- if .Values.global.registry.url -}}
{{- print .Values.global.registry.url -}}
{{- else -}}
{{- print .Values.imageCredentials.registry.url -}}
{{- end -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "eric-enm-modeldeployservice.pullSecrets" -}}
{{- if .Values.imageCredentials.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- else if .Values.global.pullSecret -}}
{{- print .Values.global.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Generate Image Repo
*/}}
{{- define "eric-enm-modeldeployservice.repo-path" }}
{{- if .Values.testEnvironment.enabled -}}
{{- print .Values.testEnvironment.image.repoPath -}}
{{- else -}}
{{- print .Values.imageCredentials.repoPath -}}
{{- end -}}
{{- end -}}

{{/*
Generate Image Tag
*/}}
{{- define "eric-enm-modeldeployservice.image-tag" }}
{{- if .Values.testEnvironment.enabled -}}
{{- print .Values.testEnvironment.image.tag -}}
{{- else -}}
{{- print (index .Values "images" "eric-enm-modeldeployservice" "tag") -}}
{{- end -}}
{{- end -}}

{{/*
Semi-colon separated list of backup types
*/}}
{{- define "eric-enm-modeldeployservice.backupTypes" }}
{{- range $i, $e := .Values.brAgent.backupTypeList -}}
{{- if eq $i 0 -}}{{- printf " " -}}{{- else -}}{{- printf ";" -}}{{- end -}}{{- . -}}
{{- end -}}
{{- end -}}
{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "stateless-integration.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "stateless-integration.fullname" -}}
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
{{- define "stateless-integration.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create image registry url
*/}}
{{- define "stateless-integration.registryUrl" -}}
{{- if .Values.global.registry.url -}}
{{- print .Values.global.registry.url -}}
{{- else -}}
{{- print .Values.imageCredentials.registry.url -}}
{{- end -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "stateless-integration.pullSecrets" -}}
{{- if .Values.global.registry.pullSecret -}}
{{- print .Values.global.registry.pullSecret -}}
{{- else if .Values.imageCredentials.registry.pullSecret -}}
{{- print .Values.imageCredentials.registry.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Create ingress hosts
*/}}
{{- define "stateless-integration.enmHost" -}}
{{- if .Values.global.ingress.enmHost -}}
{{- print .Values.global.ingress.enmHost -}}
{{- else if .Values.ingress.enmHost -}}
{{- print .Values.ingress.enmHost -}}
{{- end -}}
{{- end -}}

{{/*
Create replicas
*/}}
{{- define "stateless-integration.replicas" -}}
{{- if index .Values "global" "replicas-enm_installation" -}}
{{- print (index .Values "global" "replicas-enm_installation") -}}
{{- else if index .Values "replicas-enm_installation" -}}
{{- print (index .Values "replicas-enm_installation") -}}
{{- end -}}
{{- end -}}

{{/*
Create Storage Class
*/}}
{{- define "stateless-integration.storageClass" -}}
{{- if .Values.global.persistentVolumeClaim.storageClass -}}
{{- print .Values.global.persistentVolumeClaim.storageClass -}}
{{- else if .Values.persistentVolumeClaim.storageClass -}}
{{- print .Values.persistentVolumeClaim.storageClass -}}
{{- end -}}
{{- end -}}

{{/*
Generate chart secret name
*/}}
{{- define "stateless-integration.secretName" -}}
{{ default (include "stateless-integration.fullname" .) .Values.existingSecret }}
{{- end -}}

{{/*
The BRO restore post-install job name
*/}}
{{- define "stateless-integration.broRestorePostInstallName" -}}
{{- print "eric-enm-bro-post-restore-stateless-job" -}}
{{- end -}}

{{/*
  Returns the ServiceAccount name used for rollback/restore actions.
  Defaults to restore-service-account
*/}}
{{- define "stateless-integration.broServiceAccountName" -}}
{{ default (printf "restore-service-account" ) .Values.global.restore.serviceaccount.name }}
{{- end -}}

{{/*
repoPath for the eric-enm-chart-hooks to allow image version from dev repos.
*/}}
{{- define "stateless-integration.hookImageRepoPath" -}}
{{- if index .Values "images" "eric-enm-chart-hooks" "repoPath" -}}
{{- print (index .Values "images" "eric-enm-chart-hooks" "repoPath") -}}
{{- else -}}
{{- print .Values.imageCredentials.repoPath -}}
{{- end -}}
{{- end -}}

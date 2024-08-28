{{/* vim: set filetype=mustache: */}}

{{/*
Expand the name of the chart.
*/}}
{{- define "eric-enm-credm-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-enm-credm-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Generate Product info
*/}}
{{- define "eric-enm-credm-controller.product-info" }}
ericsson.com/product-name: "helm-eric-enm-credm-controller"
ericsson.com/product-number: "{{.Values.productNumber}}"
ericsson.com/product-revision: "{{.Values.productRevision}}"
{{- if .Values.annotations }}
{{ toYaml .Values.annotations }}
{{- end }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "eric-enm-credm-controller.fullname" -}}
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
Create the name of the service account to use
*/}}
{{- define "eric-enm-credm-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "eric-enm-credm-controller.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "eric-enm-credm-controller.labels" -}}
app: {{ .Values.service.name }}
helm.sh/chart: {{ include "eric-enm-credm-controller.chart" . }}
app.kubernetes.io/name: {{ include "eric-enm-credm-controller.name" . }}
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
Create replicas
*/}}
{{- define "eric-enm-credm-controller.replicas" -}}
{{- if index .Values "global" "replicas-eric-enm-credm-controller" -}}
{{- print (index .Values "global" "replicas-eric-enm-credm-controller") -}}
{{- end -}}
{{- end -}}

{{/*
Create image registry url
*/}}
{{- define "eric-enm-credm-controller.registryUrl" -}}
{{- if .Values.global.registry.url -}}
{{- print .Values.global.registry.url -}}
{{- else -}}
{{- print .Values.imageCredentials.registry.url -}}
{{- end -}}
{{- end -}}

{{/*
Create Storage Class
*/}}
{{- define "eric-enm-credm-controller.storageClass" -}}
{{- if .Values.global.persistentVolumeClaim.storageClass -}}
{{- print .Values.global.persistentVolumeClaim.storageClass -}}
{{- else if .Values.persistentVolumeClaim.storageClass -}}
{{- print .Values.persistentVolumeClaim.storageClass -}}
{{- end -}}
{{- end -}}


{{/*
Create image pull secrets
*/}}
{{- define "eric-enm-credm-controller.pullSecrets" -}}
{{- if .Values.global.pullSecret -}}
{{- print .Values.global.pullSecret -}}
{{- else if .Values.imageCredentials.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Create ingress hosts
*/}}
{{- define "eric-enm-credm-controller.enmHost" -}}
{{- if .Values.global.ingress.enmHost -}}
{{- print .Values.global.ingress.enmHost -}}
{{- else if .Values.ingress.enmHost -}}
{{- print .Values.ingress.enmHost -}}
{{- end -}}
{{- end -}}

{{/*
Create enmhost shortname from FQDN.
*/}}
{{- define "eric-enm-credm-controller.enmHostShort" -}}
{{- if .Values.global.ingress.enmHost -}}
{{- print ((split "." .Values.global.ingress.enmHost)._0) -}}
{{- else if .Values.ingress.enmHost -}}
{{- print ((split "." .Values.ingress.enmHost)._0) -}}
{{- end -}}
{{- end -}}



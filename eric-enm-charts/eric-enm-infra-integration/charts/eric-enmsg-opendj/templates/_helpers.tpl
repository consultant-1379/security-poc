{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "eric-enmsg-opendj.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "eric-enmsg-opendj.fullname" -}}
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
Create a default fully qualified label.
*/}}
{{- define "eric-enmsg-opendj.labels" -}}
{{- printf "app.kubernetes.io/name: \"%s" .Values.service.name }}
{{- printf "\"" -}}
{{- printf "\n" -}}
{{- printf "app.kubernetes.io/instance: \"%s" .Release.Name | trunc 63 | trimSuffix "-" | indent 4 -}}
{{- printf "\"" -}}
{{- printf "\n" -}}
{{- printf "app.kubernetes.io/version: %s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | indent 4 -}}
{{- if .Values.labels }}
{{ toYaml .Values.labels }}
{{- end }}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-enmsg-opendj.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "{{.Chart.Name}}.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Chart version.
*/}}
{{- define "{{.Chart.Name}}.version" -}}
{{- printf "%s" .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "{{.Chart.Name}}.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Ericsson product info annotations. The Chart version should match the product information.
*/}}
{{- define "eric-enmsg-opendj.prodInfoAnnotations" }}
ericsson.com/product-name: "eric-enmsg-opendj"
ericsson.com/product-number: "XXXXXXX"
ericsson.com/product-revision: "{{.Values.productRevision}}"
{{- end -}}

{{/*
Create image registry url
*/}}
{{- define "eric-enmsg-opendj.registryUrl" -}}
{{- if .Values.global.registry.url -}}
{{- print .Values.global.registry.url -}}
{{- else -}}
{{- print .Values.imageCredentials.registry.url -}}
{{- end -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "eric-enmsg-opendj.pullSecrets" -}}
{{- if .Values.global.pullSecret -}}
{{- print .Values.global.pullSecret -}}
{{- else if .Values.imageCredentials.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Create ingress hosts
*/}}
{{- define "eric-enmsg-opendj.enmHost" -}}
{{- if .Values.global.ingress.enmHost -}}
{{- print .Values.global.ingress.enmHost -}}
{{- else if .Values.ingress.enmHost -}}
{{- print .Values.ingress.enmHost -}}
{{- end -}}
{{- end -}}

{{/*
Create enmHost shortname from FQDN
*/}}
{{- define "eric-enmsg-opendj.enmHostShort" -}}
{{- if .Values.global.ingress.enmHost -}}
{{- print ((split "." .Values.global.ingress.enmHost)._0) -}}
{{- else if .Values.ingress.enmHost -}}
{{- print ((split "." .Values.global.ingress.enmHost)._0) -}}
{{- end -}}
{{- end -}}

{{/*
Create replicas
*/}}
{{- define "eric-enmsg-opendj.replicas" -}}
{{- if index .Values "global" "replicas-eric-enmsg-opendj" -}}
{{- print (index .Values "global" "replicas-eric-enmsg-opendj") -}}
{{- end -}}
{{- end -}}

{{/*
Create Storage Class
*/}}
{{- define "eric-enmsg-opendj.storageClassName" -}}
{{- if .Values.global.persistentVolumeClaim.storageClass -}}
{{- print .Values.global.persistentVolumeClaim.storageClass -}}
{{- else if .Values.persistentVolumeClaim.storageClassName -}}
{{- print .Values.persistentVolumeClaim.storageClassName -}}
{{- end -}}
{{- end -}}

{{/*
Generate chart secret name
*/}}
{{- define "eric-enmsg-opendj.secretName" -}}
{{ default (include "eric-enmsg-opendj.fullname" .) .Values.existingSecret }}
{{- end -}}

{{/*
Generate Product info
*/}}
{{- define "eric-enmsg-opendj.product-info" }}
ericsson.com/product-name: "helm-eric-enmsg-opendj"
ericsson.com/product-number: "CXC 174 2507"
ericsson.com/product-revision: "{{.Values.productRevision}}"
{{- if .Values.annotations }}
{{ toYaml .Values.annotations }}
{{- end }}
{{- end}}

{{/*
 Returns the restore <property> in the provided restorePropertyPath or fallback to brAgent.restore.<property>
*/}}
{{- define "{{.Chart.Name}}.restore" -}}
{{- $proptpl := printf "{{ .Values.%s.%s }}" (default "brAgent.restore" (last .).Values.brAgent.restorePropertyPath ) (first .) -}}
{{- $value := tpl $proptpl (last .) -}}
{{- printf "%s" $value -}}
{{- end -}}

{{/*
 Returns the restore state in the provided restorePropertyPath or fallback to brAgent.restore.state
*/}}
{{- define "{{.Chart.Name}}.restore.state" -}}
{{- include "{{.Chart.Name}}.restore" (list "state" .) -}}
{{- end -}}

{{/*
  Returns the ServiceAccount name. Defaults to <Chart.Name>-bragent
*/}}
{{- define "{{.Chart.Name}}.serviceAccountName" -}}
{{ default (printf "%s-bragent" (include "{{.Chart.Name}}.name" .)) .Values.brAgent.serviceAccount.name }}
{{- end -}}


{{/*
Semi-colon separated list of backup types
*/}}
{{- define "{{.Chart.Name}}.backupTypes" }}
  {{- range $i, $e := .Values.brAgent.backupTypeList -}}
    {{- if eq $i 0 -}}{{- printf " " -}}{{- else -}}{{- printf ";" -}}{{- end -}}{{- . -}}
  {{- end -}}
{{- end -}}

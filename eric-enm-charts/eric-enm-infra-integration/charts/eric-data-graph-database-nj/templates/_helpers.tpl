
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
{{- define "{{.Chart.Name}}.prodInfoAnnotations" }}
ericsson.com/product-name: "eric-data-graph-database-nj"
ericsson.com/product-number: "CXC 101 0901"
ericsson.com/product-revision: "{{.Values.productInfo.rstate}}"
{{- end -}}

{{/*
Ericsson product info for log-shipper templates
*/}}
{{- define "eric-data-graph-database-nj.product-info" }}
ericsson.com/product-name: "eric-data-graph-database-nj"
ericsson.com/product-number: "CXC 101 0901"
ericsson.com/product-revision: "{{.Values.productInfo.rstate}}"
{{- end }}

{{/*
Expand the name of the chart.
*/}}
{{- define "eric-data-graph-database-nj.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Ericsson immutable product info annotations. The Chart version should match the product information.
*/}}
{{- define "{{.Chart.Name}}.immutableProdInfoAnnotations" }}
ericsson.com/product-name: "eric-data-graph-database-nj"
ericsson.com/product-number: "CXC 101 0901"
{{- end -}}

{{/*
Create a default fully qualified app name for core servers.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "{{.Chart.Name}}.core.name" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s" $name | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create node pod list
*/}}
{{- define "{{.Chart.Name}}.podsname" -}}
    {{- $fullname := include "{{.Chart.Name}}.core.name" . -}}
    {{- $port := default 5000 .Values.config.port.discovery -}}
    {{- $service := include "{{.Chart.Name}}.name" . -}}
    {{- $release := .Release.Namespace -}}
    {{- $clusterdomain := default "cluster.local" .Values.config.clusterDomain -}}
    {{- $count := (int (index .Values "core" "numberOfServers")) -}}
    {{- range $v := until $count }}{{ $fullname }}-{{ $v }}.{{ $service}}.{{ $release }}.svc.{{ $clusterdomain }}:{{ $port }}{{ if ne $v (sub $count 1) }},{{- end -}}{{- end -}}
{{- end -}}

{{/*
Create a parameter list
*/}}
{{- define "{{.Chart.Name}}.parameters" -}}
{{- $local := dict "first" true -}}
{{- range $k, $v := . -}}{{- if not $local.first -}}{{- "~" -}}{{- end -}}{{- $k -}}{{- "=" -}}{{- $v | quote -}}{{- $_ := set $local "first" false -}}{{- end -}}
{{- end -}}

{{/*
Create a default fully qualified app name for read replica servers.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "{{.Chart.Name}}.replica.name" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-replica" $name | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
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
Create a default fully qualified app name for physical volumes
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "{{.Chart.Name}}.pv.name" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-pv" $name | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name for physical volumes claims
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "{{.Chart.Name}}.pvc.name" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-pvc" $name | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name for logs physical volumes claims
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "{{.Chart.Name}}.pvc.logs.name" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-logs-pvc" $name | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name for backup physical volumes claims
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "{{.Chart.Name}}.pvc.backup.name" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-bck-pvc" $name | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

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
{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "eric-net-ingress-l4.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "eric-net-ingress-l4.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- $name := default .Chart.Name -}}
{{- printf "%s-%s" $name .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-net-ingress-l4.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart version as used by the version label.
*/}}
{{- define "eric-net-ingress-l4.version" -}}
{{- printf "%s" .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Generate common labels
*/}}
{{- define "eric-net-ingress-l4.common-labels" }}
app.kubernetes.io/name: {{ include "eric-net-ingress-l4.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/version: {{ template "eric-net-ingress-l4.version" . }}
{{- if .Values.labels }}
{{ toYaml .Values.labels }}
{{- end }}
{{- end }}

{{/*
Create chart version as used by the chart annotation.
*/}}
{{- define "eric-net-ingress-l4.short-version" -}}
{{- $tmp := printf "%s" .Chart.Version -}}
{{- $tmp := replace "+" "-" $tmp -}}
{{- $tmp := split "-" $tmp -}}
{{- print $tmp._0 -}}
{{- end -}}

{{/*
Create image registry url
*/}}
{{- define "eric-net-ingress-l4.registryUrl" -}}
    {{- $registryUrl := "armdocker.rnd.ericsson.se" -}}
    {{- if .Values.global.registry.url -}}
        {{- $registryUrl = .Values.global.registry.url -}}
    {{- end -}}
    {{- if .Values.imageCredentials.registry.url -}}
        {{- $registryUrl = .Values.imageCredentials.registry.url -}}
    {{- end -}}
    {{- print $registryUrl -}}
{{- end -}}

{{/*
Create image registry url and repo path
*/}}
{{- define "eric-net-ingress-l4.registryUrlPath" -}}
{{- include "eric-net-ingress-l4.registryUrl" . }}/{{ .Values.imageCredentials.repoPath }}
{{- end -}}

{{/*
Create image registry url and development repo path
*/}}
{{- define "eric-net-ingress-l4.devregistryUrlPath" -}}
{{- include "eric-net-ingress-l4.registryUrl" . }}/{{ .Values.imageCredentials.devRepoPath }}
{{- end -}}

{{/*
Create image pull policy
*/}}
{{- define "eric-net-ingress-l4.imagePullPolicy" -}}
    {{- $globalRegistryImagePullPolicy := "Always" -}}
    {{- if .Values.global.registry.imagePullPolicy -}}
        {{- $globalRegistryImagePullPolicy = .Values.global.registry.imagePullPolicy -}}
    {{- end -}}
    {{- if .Values.imageCredentials.registry.imagePullPolicy -}}
        {{- $globalRegistryImagePullPolicy = .Values.imageCredentials.imagePullPolicy -}}
    {{- end -}}
    {{- print $globalRegistryImagePullPolicy -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "eric-net-ingress-l4.pullSecrets" -}}
{{- if .Values.global.pullSecret -}}
{{- print .Values.global.pullSecret -}}
{{- else if .Values.imageCredentials.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Create replicas
*/}}
{{- define "eric-net-ingress-l4.replicas" -}}
{{- if index .Values "global" "replicas-eric-net-ingress-l4" -}}
{{- print (index .Values "global" "replicas-eric-net-ingress-l4") -}}
{{- else if index .Values "replicas-eric-net-ingress-l4" -}}
{{- print (index .Values "replicas-eric-net-ingress-l4") -}}
{{- end -}}
{{- end -}}

{{/*
Generate ServiceAccount name.
*/}}
{{- define "eric-net-ingress-l4.serviceAccount" -}}
  {{ default (include "eric-net-ingress-l4.fullname" .) .Values.rbac.serviceAccountName }}
{{- end -}}

{{/*
Generate Comma Separated List for Excluded Ports
*/}}
{{- define "eric-net-ingress-l4.list" -}}
{{- $local := dict "first" true -}}
{{- range $k, $v := . -}}{{- if not $local.first -}},{{- end -}}{{- $v -}}{{- $_ := set $local "first" false -}}{{- end -}}
{{- end -}}

{{/*
Generate Comma Separated List for VIP Name and Address
*/}}
{{- define "eric-net-ingress-l4.vips" -}}
{{- $local := dict "first" true -}}
{{- range $k, $v := . -}}{{- if not $local.first -}},{{- end -}}{{- $k -}}={{- $v -}}{{- $_ := set $local "first" false -}}{{- end -}}
{{- end -}}

{{/*
 Create Ericsson product specific annotations
*/}}
{{- define "eric-net-ingress-l4.product-info" }}
ericsson.com/product-name: "Layer 4 Ingress Controller"
ericsson.com/product-number: "CXC Placeholder"
ericsson.com/product-revision: {{.Values.productRevision}}
{{- end}}

{{/*
Generate sidecar(s) containers if any.
*/}}
{{- define "eric-net-ingress-l4.sidecars" -}}
{{ $registryUrl := (include "eric-net-ingress-l4.registryUrlPath" .) -}}
{{ $devregistryUrl := (include "eric-net-ingress-l4.devregistryUrlPath" .) -}}
{{ $globalRegistryImagePullPolicy := (include "eric-net-ingress-l4.imagePullPolicy" .) -}}
{{- range $sidecar, $val := index .Values  "sidecars" }}
{{- if $val.enabled }}
- name: {{ $sidecar }}
{{- range $image, $imgval := index $.Values "images" }}
{{- if eq $sidecar $image }}
{{- if $.Values.dev }}
  image: {{ $devregistryUrl }}/{{ $imgval.name }}:{{ $imgval.tag }}
{{- else }}
  image: {{ $registryUrl }}/{{ $imgval.name }}:{{ $imgval.tag }}
{{- end }}
  imagePullPolicy: {{ $globalRegistryImagePullPolicy }}
{{- end }}
{{- end }}
{{- if $val.resources }}
  resources:
    requests:
      memory: {{ $val.resources.requests.memory | quote }}
      cpu: {{ $val.resources.requests.cpu | quote }}
    limits:
      memory: {{ $val.resources.limits.memory | quote }}
      cpu: {{ $val.resources.limits.cpu | quote }}
{{- end }}
{{- if $val.env }}
  env:
{{- if eq $sidecar "eric-enm-snmp-trap-forwarder" }}
    - name: SNMP_TRAP_RECEIVER_PORT
      value: {{ $val.env.SNMP_TRAP_RECEIVER_PORT | quote }}
    - name: SNMP_TRAP_FORWARDER_PORT
      value: {{ $val.env.SNMP_TRAP_FORWARDER_PORT | quote }}
    - name: APG_SNMP_TRAP_RECEIVER_PORT
      value: {{ $val.env.APG_SNMP_TRAP_RECEIVER_PORT | quote }}
    - name: APG_SNMP_TRAP_FORWARDER_PORT
      value: {{ $val.env.APG_SNMP_TRAP_FORWARDER_PORT | quote }}
    - name: svc_FM_vip_ipaddress
      value: {{ $.Values.global.vips.fm_vip_address }}
    - name: svc_FM_vip_fwd_ipaddress
      value: {{ $.Values.global.vips.svc_FM_vip_fwd_ipaddress }}
    - name: TZ
      value: {{ $.Values.global.timezone }}
    - name: POD_IP
      valueFrom:
        fieldRef:
          fieldPath: status.podIP
{{- else if eq $sidecar "eric-enm-http-alarms-forwarder" }}
    - name: svc_FM_vip_ipaddress
      value: {{ $.Values.global.vips.fm_vip_address }}
    - name: TZ
      value: {{ $.Values.global.timezone }}
    - name: POD_IP
      valueFrom:
        fieldRef:
          fieldPath: status.podIP
    - name: HTTP_PORT
      value: {{ $val.env.HTTP_PORT | quote }}
    - name: SECURE_HTTP_PORT
      value: {{ $val.env.SECURE_HTTP_PORT | quote }}
{{- else -}}
{{- range $envvar, $envval := index $val.env }}
    - name: {{ $envvar }}
      value: {{ $envval }}
{{- end }}
{{- end }}
{{- end }}
  volumeMounts:
  - name: scripts-vol
    mountPath: /scripts
  - name: scripts-exec-vol
    mountPath: /scripts-exec
{{- if $val.volumeMounts }}
{{- range $volm, $volmval := index $val.volumeMounts }}
  - name: {{ $volmval.name }}
    mountPath: {{ $volmval.mountPath }}
{{- end }}
{{- end }}
{{- if $val.lifecycle }}
  lifecycle:
{{ toYaml $val.lifecycle | indent 4 }}
{{- end }}
{{- if $val.securityContext }}
  securityContext:
{{ toYaml $val.securityContext | indent 4 }}
{{- end }}
{{- if $val.readinessProbe }}
  readinessProbe:
{{ toYaml $val.readinessProbe | indent 4 }}
{{- end }}
{{- if $val.livenessProbe }}
  livenessProbe:
{{ toYaml $val.livenessProbe | indent 4 }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

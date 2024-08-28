{{/*
Generate WPServ Instances Dynamically
*/}}
{{- define "{{.Chart.Name}}.podsname" -}}
    {{- $release := .Release.Namespace -}}
    {{- "wpserv" }}.{{ $release }}.svc.cluster.local
{{- end -}}

{{/*
Generate Product info
*/}}
{{- define "product-info" }}
ericsson.com/product-name: {{ .Chart.Name }}
ericsson.com/product-number: {{ .Values.productNumber }}
ericsson.com/product-revision: {{ .Values.productRevision }}
{{- end}}

{{/*
 Create image pull secrets
*/}}
{{- define "eric-enmsg-general-scripting.pullSecrets" -}}
{{- if .Values.global.registry.pullSecret -}}
{{- print .Values.global.pullSecret -}}
{{- else if .Values.imageCredentials.registry.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- end -}}
{{- end -}}
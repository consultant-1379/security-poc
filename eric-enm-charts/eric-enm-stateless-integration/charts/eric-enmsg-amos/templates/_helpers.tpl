{{/*
Generate WPServ Instances Dynamically
*/}}
{{- define "{{.Chart.Name}}.podsname" -}}
    {{- $release := .Release.Namespace -}}
    {{- "wpserv" }}.{{ $release }}.svc.cluster.local
{{- end -}}

{{/*
 Create image pull secrets
*/}}
{{- define "eric-enmsg-amos.pullSecrets" -}}
{{- if .Values.global.registry.pullSecret -}}
{{- print .Values.global.pullSecret -}}
{{- else if .Values.imageCredentials.registry.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- end -}}
{{- end -}}
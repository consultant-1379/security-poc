{{/*
Generate WPServ Instances Dynamically
*/}}
{{- define "{{.Chart.Name}}.podsname" -}}
    {{- $release := .Release.Namespace -}}
    {{- "wpserv" }}.{{ $release }}.svc.cluster.local
{{- end -}}

{{/*
Generate IPSMServ Instances Dynamically
*/}}
{{- define "ipsmservice.podsname" -}}
    {{- $release := .Release.Namespace -}}
    {{- "ipsmserv" }}.{{ $release }}.svc.cluster.local
{{- end -}}

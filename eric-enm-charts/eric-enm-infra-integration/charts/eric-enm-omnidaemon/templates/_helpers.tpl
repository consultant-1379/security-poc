{{/*
Chart version.
*/}}
{{- define "{{.Chart.Name}}.version" -}}
{{- printf "%s" .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Semi-colon separated list of backup types
*/}}
{{- define "{{.Chart.Name}}.backupTypes" }}
  {{- range $i, $e := .Values.brAgent.backupTypeList -}}
    {{- if eq $i 0 -}}{{- printf " " -}}{{- else -}}{{- printf ";" -}}{{- end -}}{{- . -}}
  {{- end -}}
{{- end -}}
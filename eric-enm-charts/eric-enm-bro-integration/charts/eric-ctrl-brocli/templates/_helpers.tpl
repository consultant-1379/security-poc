{{/*
Expand the name of the chart.
*/}}
{{- define "eric-ctrl-brocli.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-ctrl-brocli.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "eric-ctrl-brocli.labels" -}}
helm.sh/chart: {{ include "eric-ctrl-brocli.chart" . }}
{{ include "eric-ctrl-brocli.selectorLabels" . }}
{{- if .Chart.Version }}
app.kubernetes.io/version: {{ .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "eric-ctrl-brocli.selectorLabels" -}}
app.kubernetes.io/name: {{ include "eric-ctrl-brocli.name" . }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end }}

{{/*
Ericsson product info values.
*/}}
{{- define "eric-ctrl-brocli.productName" -}}
{{- $productInfo := fromYaml (.Files.Get "eric-product-info.yaml") -}}
{{- printf "%s" $productInfo.productName -}}
{{- end -}}
{{- define "eric-ctrl-brocli.productNumber" -}}
{{- $productInfo := fromYaml (.Files.Get "eric-product-info.yaml") -}}
{{- printf "%s" $productInfo.productNumber -}}
{{- end -}}

{{/*
Generate Product info
*/}}
{{- define "eric-ctrl-brocli.product-info" }}
ericsson.com/product-name: {{ template "eric-ctrl-brocli.productName" . }}
ericsson.com/product-number: {{ template "eric-ctrl-brocli.productNumber" . }}
ericsson.com/product-revision: {{ regexReplaceAll "(.*)[+].*" .Chart.Version "${1}" }}
{{- if .Values.annotations }}
{{ toYaml .Values.annotations }}
{{- end }}
{{- end}}

{{/*
 Create image pull secrets
 */}}
{{- define "eric-ctrl-brocli.pullsecret" -}}
{{- if .Values.imageCredentials }}
  {{- if .Values.imageCredentials.pullSecret }}
      imagePullSecrets:
        - name: {{ .Values.imageCredentials.pullSecret | quote}}
  {{- else if .Values.global -}}
      {{- if .Values.global.pullSecret }}
      imagePullSecrets:
        - name: {{ .Values.global.pullSecret | quote }}
      {{- end -}}
  {{- end }}
{{- else if .Values.global -}}
  {{- if .Values.global.pullSecret }}
      imagePullSecrets:
        - name: {{ .Values.global.pullSecret | quote }}
  {{- end -}}
{{- end }}
{{- end -}}


{{/*
The brocli Image path (DR-D1121-067)
*/}}
{{- define "eric-ctrl-brocli.ImagePath" }}
    {{- $productInfo := fromYaml (.Files.Get "eric-product-info.yaml") -}}
    {{- $registryUrl := $productInfo.images.backupAndRestoreCli.registry -}}
    {{- $repoPath := $productInfo.images.backupAndRestoreCli.repoPath -}}
    {{- $name := $productInfo.images.backupAndRestoreCli.name -}}
    {{- $tag := $productInfo.images.backupAndRestoreCli.tag -}}
    {{- if .Values.global -}}
        {{- if .Values.global.registry -}}
            {{- if .Values.global.registry.url -}}
                {{- $registryUrl = .Values.global.registry.url -}}
            {{- end -}}
        {{- end -}}
    {{- end -}}
    {{- if .Values.imageCredentials -}}
        {{- if .Values.imageCredentials.registry -}}
            {{- if .Values.imageCredentials.registry.url -}}
                {{- $registryUrl = .Values.imageCredentials.registry.url -}}
            {{- end -}}
        {{- end -}}
    {{- end -}}
    {{- if not (kindIs "invalid" .Values.imageCredentials.repoPath) -}}
        {{- $repoPath = .Values.imageCredentials.repoPath -}}
    {{- end -}}
    {{- if $repoPath -}}
        {{- $repoPath = printf "%s/" $repoPath -}}
    {{- end -}}
    {{- if $tag -}}
    {{- printf "%s/%s%s:%s" $registryUrl $repoPath $name $tag -}}
    {{- else }}
    {{- printf "%s/%s%s" $registryUrl $repoPath $name -}}
{{- end -}}
{{- end -}}

{{/*
 Create image pull policy
 */}}
{{- define "eric-ctrl-brocli.pullpolicy" -}}
{{- $defaultPolicy := "IfNotPresent" -}}
{{- $imgCred := .Values.imageCredentials | default dict -}}
{{- $reg := $imgCred.registry | default dict -}}
{{- if $reg.imagePullPolicy -}}
imagePullPolicy: {{ .Values.imageCredentials.registry.imagePullPolicy | quote }}
{{- else if .Values.global.registry -}}
imagePullPolicy: {{ default $defaultPolicy .Values.global.registry.imagePullPolicy | quote }}
{{- else -}}
imagePullPolicy: {{ $defaultPolicy | quote }}
{{- end -}}
{{- end -}}
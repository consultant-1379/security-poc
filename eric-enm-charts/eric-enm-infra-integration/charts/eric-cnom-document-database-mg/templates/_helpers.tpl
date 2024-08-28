{{/*
Expand the name of the chart.
*/}}
{{- define "eric-cnom-document-database-mg.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart version as used by the chart label.
*/}}
{{- define "eric-cnom-document-database-mg.version" -}}
{{- printf "%s" .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-cnom-document-database-mg.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a map from ".Values.global" with defaults if missing in values file.
This hides defaults from values file.
*/}}
{{ define "eric-cnom-document-database-mg.global" }}
  {{- $globalDefaults := dict "timezone" "UTC" -}}
  {{- $globalDefaults := merge $globalDefaults (dict "registry" (dict "url" "selndocker.mo.sw.ericsson.se")) -}}
  {{- $globalDefaults := merge $globalDefaults (dict "pullSecret" "") -}}
  {{- $globalDefaults := merge $globalDefaults (dict "nodeSelector" (dict)) -}}
  {{- $globalDefaults := mustMerge $globalDefaults (dict "registry" (dict "imagePullPolicy" "IfNotPresent")) -}}
  {{ if .Values.global }}
    {{- mergeOverwrite $globalDefaults .Values.global | toJson -}}
  {{ else }}
    {{- $globalDefaults | toJson -}}
  {{ end }}
{{ end }}

{{/*
Create image registry url
*/}}
{{- define "eric-cnom-document-database-mg.registryUrl" -}}
{{- $global := fromJson (include "eric-cnom-document-database-mg.global" .) -}}
{{- if .Values.imageCredentials.registry.url -}}
{{- print .Values.imageCredentials.registry.url -}}
{{- else -}}
{{- print $global.registry.url -}}
{{- end -}}
{{- end -}}

{{/*
Create image repoPath
*/}}
{{- define "eric-cnom-document-database-mg.repoPath" -}}
{{- if .Values.imageCredentials.repoPath -}}
{{- print "/" .Values.imageCredentials.repoPath "/" -}}
{{- else -}}
{{- print "/" -}}
{{- end -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "eric-cnom-document-database-mg.pullSecrets" -}}
{{- $global := fromJson (include "eric-cnom-document-database-mg.global" .) -}}
{{- if .Values.imageCredentials.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- else if $global.pullSecret -}}
{{- print $global.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Create image pull policy
*/}}
{{- define "eric-cnom-document-database-mg.imagePullPolicy" -}}
{{- if .Values.imageCredentials.registry.imagePullPolicy -}}
{{- print .Values.imageCredentials.registry.imagePullPolicy -}}
{{- else -}}
{{- $global := fromJson (include "eric-cnom-document-database-mg.global" .) }}
{{- print $global.registry.imagePullPolicy -}}
{{- end -}}
{{- end -}}

{{/*
Create a merged set of nodeSelectors from global and service level.
*/}}
{{ define "eric-cnom-document-database-mg.nodeSelector" }}
{{- $global := fromJson (include "eric-cnom-document-database-mg.global" .) -}}
{{- if .Values.nodeSelector -}}
  {{- range $key, $localValue := .Values.nodeSelector -}}
    {{- if hasKey $global.nodeSelector $key -}}
        {{- $globalValue := index $global.nodeSelector $key -}}
        {{- if ne $globalValue $localValue -}}
          {{- printf "nodeSelector \"%s\" is specified in both global (%s: %s) and service level (%s: %s) with differing values which is not allowed." $key $key $globalValue $key $localValue | fail -}}
        {{- end -}}
    {{- end -}}
  {{- end -}}
  {{- toYaml (merge $global.nodeSelector .Values.nodeSelector) | trim -}}
{{- else -}}
  {{- toYaml $global.nodeSelector | trim -}}
{{- end -}}
{{ end }}

{{/*
Create the name for the admin secret.
*/}}
{{- define "eric-cnom-document-database-mg.adminSecret" -}}
    {{- if .Values.auth.existingAdminSecret -}}
        {{- .Values.auth.existingAdminSecret -}}
    {{- else -}}
        {{- template "eric-cnom-document-database-mg.name" . -}}-admin
    {{- end -}}
{{- end -}}

{{/*
Create the name for the key secret.
*/}}
{{- define "eric-cnom-document-database-mg.keySecret" -}}
    {{- if .Values.auth.existingKeySecret -}}
        {{- .Values.auth.existingKeySecret -}}
    {{- else -}}
        {{- template "eric-cnom-document-database-mg.name" . -}}-keyfile
    {{- end -}}
{{- end -}}

{{/*
Return the proper Storage Class
*/}}
{{- define "eric-cnom-document-database-mg.storageClass" -}}
{{/*
Helm 2.11 supports the assignment of a value to a variable defined in a different scope,
but Helm 2.9 and 2.10 does not support it, so we need to implement this if-else logic.
*/}}
{{- $global := fromJson (include "eric-cnom-document-database-mg.global" .) -}}
{{- if $global -}}
    {{- if $global.storageClass -}}
        {{- if (eq "-" $global.storageClass) -}}
            {{- printf "storageClassName: \"\"" -}}
        {{- else }}
            {{- printf "storageClassName: %s" $global.storageClass -}}
        {{- end -}}
    {{- else -}}
        {{- if .Values.persistence.storageClass -}}
              {{- if (eq "-" .Values.persistence.storageClass) -}}
                  {{- printf "storageClassName: \"\"" -}}
              {{- else }}
                  {{- printf "storageClassName: %s" .Values.persistence.storageClass -}}
              {{- end -}}
        {{- end -}}
    {{- end -}}
{{- else -}}
    {{- if .Values.persistence.storageClass -}}
        {{- if (eq "-" .Values.persistence.storageClass) -}}
            {{- printf "storageClassName: \"\"" -}}
        {{- else }}
            {{- printf "storageClassName: %s" .Values.persistence.storageClass -}}
        {{- end -}}
    {{- end -}}
{{- end -}}
{{- end -}}

{{/*
Returns the proper Service name depending if an explicit service name is set
in the values file. If the name is not explicitly set it will take the "eric-cnom-document-database-mg.name"
*/}}
{{- define "eric-cnom-document-database-mg.serviceName" -}}
  {{- if .Values.service.name -}}
    {{ .Values.service.name }}
  {{- else -}}
    {{ template "eric-cnom-document-database-mg.name" .}}
  {{- end -}}
{{- end -}}

{{/*
Returns the database host string.
*/}}
{{- define "eric-cnom-document-database-mg.host" -}}
  {{- if .Values.replicaSet.enabled }}
    {{- $hosts := list }}
    {{- $root := . }}
    {{- range $i, $e := until (int .Values.replicaSet.replicaCount) }}
    {{- $hosts = append $hosts (printf "%s-%d:%s" (include "eric-cnom-document-database-mg.serviceName" $root) $i (toString $.Values.service.port)) }}
    {{- end }}
    {{- printf "%s/%s" "rs0" (join "," $hosts) }}
  {{- else }}
    {{- printf "%s:%s" (include "eric-cnom-document-database-mg.serviceName" .) (toString .Values.service.port) }}
  {{- end }}
{{- end -}}

{{/*
Return Ericsson product information which should be appended in all resource annotations.
*/}}
{{- define "eric-cnom-document-database-mg.product-info" -}}
ericsson.com/product-name: {{ include "eric-cnom-document-database-mg.product-name" . }}
ericsson.com/product-number: {{ include "eric-cnom-document-database-mg.product-number" . }}
ericsson.com/product-revision: {{ include "eric-cnom-document-database-mg.product-revision" . }}
ericsson.com/production-date: {{ include "eric-cnom-document-database-mg.production-date" . }}
{{- end }}

{{/*
Return Ericsson product name.
*/}}
{{- define "eric-cnom-document-database-mg.product-name" -}}
{{- printf "CNOM Document Database" -}}
{{- end }}

{{/*
Return Ericsson product number.
*/}}
{{- define "eric-cnom-document-database-mg.product-number" -}}
{{- printf "CXC 174 2250" -}}
{{- end }}

{{/*
Return Ericsson product revision.
*/}}
{{- define "eric-cnom-document-database-mg.product-revision" -}}
{{- mustRegexReplaceAll "(.*)[+|-].*" .Chart.Version "${1}" | quote }}
{{- end }}

{{/*
Return Ericsson production date. This is not required by the ADP design rule.
But in BRA ConfigMap, this product information is essential.
*/}}
{{- define "eric-cnom-document-database-mg.production-date" -}}
{{- .Values.productInfo.productionDate -}}
{{- end }}
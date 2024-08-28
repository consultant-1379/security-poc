{{/* vim: set filetype=mustache: */}}

{{/*
The ingresscontroller image path (DR-D1121-067)
*/}}
{{- define "eric-oss-ingress-controller-nx.ingresscontroller.imagePath" }}
    {{- $productInfo := fromYaml (.Files.Get "eric-product-info.yaml") -}}
    {{- $registryUrl := $productInfo.images.ingresscontroller.registry -}}
    {{- $repoPath := $productInfo.images.ingresscontroller.repoPath -}}
    {{- $name := $productInfo.images.ingresscontroller.name -}}
    {{- $tag := $productInfo.images.ingresscontroller.tag -}}
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
            {{- if .Values.imageCredentials.repoPath -}}
                {{- $repoPath = .Values.imageCredentials.repoPath -}}
            {{- end -}}
    {{- end -}}
    {{- if .Values.images -}}
        {{- if .Values.images.ingresscontroller -}}
            {{- if .Values.images.ingresscontroller.name -}}
                {{- $name = .Values.images.ingresscontroller.name -}}
            {{- end -}}
            {{- if .Values.images.ingresscontroller.tag -}}
                {{- $tag = .Values.images.ingresscontroller.tag -}}
            {{- end -}}
        {{- end -}}
    {{- end -}}
    {{- if $repoPath -}}
        {{- $repoPath = printf "%s/" $repoPath -}}
    {{- end -}}
    {{- printf "%s/%s%s:%s" $registryUrl $repoPath $name $tag -}}
{{- end -}}


{{/*
Expand the name of the chart.
*/}}
{{- define "eric-oss-ingress-controller-nx.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "eric-oss-ingress-controller-nx.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create version
*/}}
{{- define "eric-oss-ingress-controller-nx.version" -}}
{{- printf "%s" .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "eric-oss-ingress-controller-nx.fullname" -}}
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
Create a user defined config labels (DR-D1121-068)
*/}}
{{ define "eric-oss-ingress-controller-nx.config-labels" }}
{{- if .Values.labels -}}
{{- range $name, $config := .Values.labels }}
{{ $name }}: {{ tpl $config $ }}
{{- end }}
{{- end }}
{{- end}}


{{/*
Create the name of the service account to use
*/}}
{{- define "eric-oss-ingress-controller-nx.serviceAccountName" -}}
{{ default (printf "%s-%s" (include "eric-oss-ingress-controller-nx.name" .) "sa") .Values.serviceAccount.name }}
{{- end -}}


{{- define "eric-oss-ingress-controller-nx.registryImagePullPolicy" -}}
    {{- $globalRegistryPullPolicy := "IfNotPresent" -}}
    {{- if .Values.global -}}
        {{- if .Values.global.registry -}}
            {{- if .Values.global.registry.imagePullPolicy -}}
                {{- $globalRegistryPullPolicy = .Values.global.registry.imagePullPolicy -}}
            {{- end -}}
        {{- end -}}
    {{- end -}}
    {{- if .Values.imageCredentials.registry -}}
        {{- if .Values.imageCredentials.registry.imagePullPolicy -}}
        {{- $globalRegistryPullPolicy = .Values.imageCredentials.registry.imagePullPolicy -}}
        {{- end -}}
    {{- end -}}
    {{- print $globalRegistryPullPolicy -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "eric-oss-ingress-controller-nx.pullSecrets" -}}
    {{- $globalPullSecret := "" -}}
    {{- if .Values.global -}}
        {{- if .Values.global.pullSecret -}}
            {{- $globalPullSecret = .Values.global.pullSecret -}}
        {{- end -}}
    {{- end -}}
    {{- if .Values.imageCredentials.pullSecret -}}
        {{- print .Values.imageCredentials.pullSecret -}}
    {{- else if $globalPullSecret -}}
        {{- print $globalPullSecret -}}
    {{- end -}}
{{- end -}}

{{/*
Create a merged set of nodeSelectors from global and service level.
*/}}
{{ define "eric-oss-ingress-controller-nx.nodeSelector" }}
  {{- $g := fromJson (include "eric-oss-ingress-controller-nx.global" .) -}}
  {{- if .Values.nodeSelector -}}
    {{- range $key, $localValue := .Values.nodeSelector -}}
      {{- if hasKey $g.nodeSelector $key -}}
          {{- $globalValue := index $g.nodeSelector $key -}}
          {{- if ne $globalValue $localValue -}}
            {{- printf "nodeSelector \"%s\" is specified in both global (%s: %s) and service level (%s: %s) with differing values which is not allowed." $key $key $globalValue $key $localValue | fail -}}
          {{- end -}}
      {{- end -}}
    {{- end -}}
    {{- toYaml (merge $g.nodeSelector .Values.nodeSelector) | trim -}}
  {{- else -}}
    {{- toYaml $g.nodeSelector | trim -}}
  {{- end -}}
{{ end }}


{{/*
Create Ericsson product specific annotations
*/}}
{{- define "eric-oss-ingress-controller-nx.product-info" }}
ericsson.com/product-name: {{ (fromYaml (.Files.Get "eric-product-info.yaml")).productName | quote }}
ericsson.com/product-number: {{ (fromYaml (.Files.Get "eric-product-info.yaml")).productNumber | quote }}
ericsson.com/product-revision: {{regexReplaceAll "(.*)[+].*" .Chart.Version "${1}" }}
{{- end -}}

{{/*
Create a user defined annotation (DR-D1121-065)
*/}}
{{ define "eric-oss-ingress-controller-nx.config-annotations" }}
{{- if .Values.annotations -}}
{{- range $name, $config := .Values.annotations }}
{{ $name }}: {{ tpl $config $ }}
{{- end }}
{{- end }}
{{- end}}


{{/*
Create a map from ".Values.global" with defaults if missing in values file.
This hides defaults from values file.
*/}}
{{ define "eric-oss-ingress-controller-nx.global" }}
  {{- $globalDefaults := dict "security" (dict "tls" (dict "enabled" true)) -}}
  {{- $globalDefaults := merge $globalDefaults (dict "registry" (dict "url" "armdocker.rnd.ericsson.se")) -}}
  {{- $globalDefaults := merge $globalDefaults (dict "registry" (dict "imagePullPolicy" "IfNotPresent")) -}}
  {{- $globalDefaults := merge $globalDefaults (dict "registry" (dict "pullSecret" "")) -}}
  {{- $globalDefaults := merge $globalDefaults (dict "timezone" "UTC") -}}
  {{- $globalDefaults := merge $globalDefaults (dict "nodeSelector" (dict)) -}}
  {{ if .Values.global }}
    {{- mergeOverwrite $globalDefaults .Values.global | toJson -}}
  {{ else }}
    {{- $globalDefaults | toJson -}}
  {{ end }}
{{ end }}


{{/*
Define extraArgs
*/}}

{{- define "eric-oss-ingress-controller-nx.extraArgs" }}
{{- if .Values.extraArgs -}}
{{- range $name, $arg := .Values.extraArgs -}}
   {{ indent 1 "--" }}{{ $name }}={{ tpl $arg $ }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Define affinity
*/}}
{{- define "eric-oss-ingress-controller-nx.affinity" -}}
{{- if eq .Values.affinity.podAntiAffinity "hard" -}}
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: app.kubernetes.io/name
          operator: In
          values:
          - {{ template "eric-oss-ingress-controller-nx.name" . }}
      topologyKey: "kubernetes.io/hostname"
{{- else if eq .Values.affinity.podAntiAffinity "soft" -}}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - {{ template "eric-oss-ingress-controller-nx.name" . }}
        topologyKey: "kubernetes.io/hostname"
{{- end -}}
{{- end -}}

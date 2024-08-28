{{/*
Expand the name of the chart.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
*/}}
{{- define "eric-cnom-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
Note: Currently we directly reference 'eric-cnom-server.name'. But this fullname template is kept
anyway so that we can change the logic here in the future without having to update templates
referencing it.
*/}}
{{- define "eric-cnom-server.fullname" -}}
{{ include "eric-cnom-server.name" . }}
{{- end }}

{{/*
Create chart version as used by the chart label.
*/}}
{{- define "eric-cnom-server.version" -}}
{{- printf "%s" .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}}

{{/*
Create chart name and version as used by the chart label
*/}}
{{- define "eric-cnom-server.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "eric-cnom-server.labels" -}}
chart: {{ include "eric-cnom-server.chart" . | quote }}
{{ include "eric-cnom-server.selectorLabels" . }}
app.kubernetes.io/version: {{ include "eric-cnom-server.version" . | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote}}
{{- if .Values.labels }}
{{ toYaml .Values.labels }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "eric-cnom-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "eric-cnom-server.name" . | quote }}
app.kubernetes.io/instance: {{ .Release.Name | quote }}
{{- end }}

{{/*
Create image path (.Values.imageCredentials.repoPath is deprecated, will be removed)
*/}}
{{- define "eric-cnom-server.imagePath" }}
{{- $productInfo := fromYaml (.Files.Get "eric-product-info.yaml") -}}
{{- $global := fromJson (include "eric-cnom-server.global" .) }}
{{- $registryUrl := default $global.registry.url (default .Values.imageCredentials.registry.url .Values.imageCredentials.server.registry.url) -}}
{{- $repoPath := printf "%s/" $productInfo.images.server.repoPath -}}
{{- if .Values.imageCredentials.server.repoPath -}}
  {{- $repoPath = printf "%s/" .Values.imageCredentials.server.repoPath -}}
{{- /* If repoPath is an empty string, we don't want to use the default */ -}}
{{- else if kindIs "string" .Values.imageCredentials.server.repoPath -}}
  {{- $repoPath = "" -}}
{{- else if .Values.imageCredentials.repoPath -}}
  {{- $repoPath = printf "%s/" .Values.imageCredentials.repoPath -}}
{{- else if kindIs "string" .Values.imageCredentials.repoPath -}}
  {{- $repoPath = "" -}}
{{- end -}}
{{- $name := default $productInfo.images.server.name .Values.images.server.name -}}
{{- $tag := default $productInfo.images.server.tag .Values.images.server.tag -}}
{{- printf "%s/%s%s:%s" $registryUrl $repoPath $name $tag -}}
{{- end -}}

{{/*
Create image pull secrets
*/}}
{{- define "eric-cnom-server.pullSecret" -}}
{{- $global := fromJson (include "eric-cnom-server.global" .) }}
{{- if .Values.imageCredentials.pullSecret -}}
{{- print .Values.imageCredentials.pullSecret -}}
{{- else if $global.pullSecret -}}
{{- print $global.pullSecret -}}
{{- end -}}
{{- end -}}

{{/*
Create image pull policy
*/}}
{{- define "eric-cnom-server.imagePullPolicy" -}}
{{- if .Values.imageCredentials.server.registry.imagePullPolicy -}}
{{- print .Values.imageCredentials.server.registry.imagePullPolicy -}}
{{- else if .Values.imageCredentials.registry.imagePullPolicy -}}
{{- print .Values.imageCredentials.registry.imagePullPolicy -}}
{{- else -}}
{{- $global := fromJson (include "eric-cnom-server.global" .) }}
{{- print $global.registry.imagePullPolicy -}}
{{- end -}}
{{- end -}}

{{/*
Create annotation for the product information (DR-D1121-064, DR-D1121-067)
*/}}
{{- define "eric-cnom-server.product-info" -}}
ericsson.com/product-name: {{ (fromYaml (.Files.Get "eric-product-info.yaml")).productName | quote }}
ericsson.com/product-number: {{ (fromYaml (.Files.Get "eric-product-info.yaml")).productNumber | quote }}
ericsson.com/product-revision: {{ mustRegexReplaceAll "(.*)[+|-].*" .Chart.Version "${1}" | quote }}
{{- end }}

{{/*
Create AppArmor annotations
*/}}
{{- define "eric-cnom-server.appArmorAnnotations" -}}
{{- if .Values.appArmorProfile -}}
{{- if .Values.appArmorProfile.server -}}
{{- if .Values.appArmorProfile.server.type -}}
{{- $profileRef := .Values.appArmorProfile.server.type -}}
{{- if eq .Values.appArmorProfile.server.type "localhost" -}}
{{- $failureMessage := "If you set appArmorProfile.server.type=localhost you are required to set appArmorProfile.server.localhostProfile" -}}
{{- $profileRef = printf "localhost/%s" (required $failureMessage .Values.appArmorProfile.server.localhostProfile) -}}
{{- end -}}
container.apparmor.security.beta.kubernetes.io/server: {{ $profileRef | quote }}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create seccomp config
*/}}
{{- define "eric-cnom-server.seccompProfile" -}}
{{- $container := . -}}
{{- if $container -}}
{{- if $container.type -}}
seccompProfile:
  type: {{ $container.type | quote }}
{{- if eq $container.type "Localhost" -}}
{{ $failureMessage := "If you set seccomp type 'Localhost' you are required to set the seccomp 'localhostProfile'" }}
  localhostProfile: {{ required $failureMessage $container.localhostProfile | quote }}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create a map from ".Values.global" with defaults if missing in values file.
This hides defaults from values file.
*/}}
{{ define "eric-cnom-server.global" }}
  {{- $productInfo := fromYaml (.Files.Get "eric-product-info.yaml") -}}
  {{- $globalDefaults := dict "security" (dict "tls" (dict "enabled" true)) -}}
  {{- $globalDefaults := mustMerge $globalDefaults (dict "security" (dict "policyBinding" (dict "create" false))) -}}
  {{- $globalDefaults := mustMerge $globalDefaults (dict "security" (dict "policyReferenceMap" (dict "default-restricted-security-policy" "default-restricted-security-policy"))) -}}
  {{- $globalDefaults := mustMerge $globalDefaults (dict "timezone" "UTC") -}}
  {{- $globalDefaults := mustMerge $globalDefaults (dict "nodeSelector" (dict)) -}}
  {{- $globalDefaults := mustMerge $globalDefaults (dict "registry" (dict "url" $productInfo.images.server.registry)) -}}
  {{- $globalDefaults := mustMerge $globalDefaults (dict "registry" (dict "imagePullPolicy" "IfNotPresent")) -}}
  {{- $globalDefaults := mustMerge $globalDefaults (dict "pullSecret" nil) -}}
  {{ if .Values.global }}
    {{- mustMergeOverwrite $globalDefaults .Values.global | mustToJson -}}
  {{ else }}
    {{- $globalDefaults | mustToJson -}}
  {{ end }}
{{ end }}

{{/*
Create a merged set of nodeSelectors from global and service level.
*/}}
{{ define "eric-cnom-server.nodeSelector" }}
{{- $global := fromJson (include "eric-cnom-server.global" .) -}}
{{- if .Values.nodeSelector -}}
  {{- range $key, $localValue := .Values.nodeSelector -}}
    {{- if hasKey $global.nodeSelector $key -}}
        {{- $globalValue := index $global.nodeSelector $key -}}
        {{- if ne $globalValue $localValue -}}
          {{- printf "nodeSelector \"%s\" is specified in both global (%s: %s) and service level (%s: %s) with differing values which is not allowed." $key $key $globalValue $key $localValue | fail -}}
        {{- end -}}
    {{- end -}}
  {{- end -}}
  {{- toYaml (mustMerge $global.nodeSelector .Values.nodeSelector) | trim -}}
{{- else -}}
  {{- toYaml $global.nodeSelector | trim -}}
{{- end -}}
{{ end }}

{{/*
TLS CA certificates for our API
*/}}
{{- define "eric-cnom-server.api.tls-ca" -}}
  {{- $endpoint := .Values.service.endpoints.api -}}
  {{- $caPaths := (list) -}}
  {{- if and (not $endpoint.tls.disableSipTls) (.Capabilities.APIVersions.Has "siptls.sec.ericsson.com/v1/InternalUserCA") -}}
    {{- $caPaths = mustAppend $caPaths "/cnom/certificates/api/sip_tls/client-cacertbundle.pem" }}
  {{- end -}}
  {{- if and .Values.ingress.enabled .Values.ingress.certificates.enabled .Values.ingress.tls.passthrough }}
    {{- $caPaths = mustAppend $caPaths "/cnom/certificates/api/certm/ca.crt" }}
  {{- end -}}
  {{- range $ca := $endpoint.tls.ca -}}
    {{- $caPaths = default "client-cacertbundle.pem" $ca.bundle | printf "/cnom/certificates/api/%s/%s" $ca.name | mustAppend $caPaths -}}
  {{- end -}}
  {{- mustUniq $caPaths| join "," | quote }}
{{- end }}

{{/*
TLS certificates for our API
*/}}
{{- define "eric-cnom-server.api.tls-certs" -}}
  {{- $endpoint := .Values.service.endpoints.api -}}
{{- if $endpoint.tls.cert -}}
  {{- if not $endpoint.tls.key }}
    {{ fail "When service.endpoints.api.tls.cert has been set, you also need to set service.endpoints.api.tls.key" }}
  {{- end }}
  {{- "/cnom/certificates/api/manually_created_secret/cert.pem" }}
{{- else if and .Values.ingress.enabled .Values.ingress.certificates.enabled .Values.ingress.tls.passthrough }}
  {{- "/cnom/certificates/api/certm/tls.crt" }}
{{- else if and (not $endpoint.tls.disableSipTls) (.Capabilities.APIVersions.Has "siptls.sec.ericsson.com/v1/InternalCertificate") -}}
  {{- "/cnom/certificates/api/sip_tls/cert.pem" }}
{{- else -}}
  {{- "" }}
{{- end -}}
{{- end }}

{{/*
TLS keys for our API
*/}}
{{- define "eric-cnom-server.api.tls-keys" -}}
  {{- $endpoint := .Values.service.endpoints.api -}}
{{- if $endpoint.tls.key -}}
  {{- if not $endpoint.tls.cert }}
    {{ fail "When service.endpoints.api.tls.key has been set, you also need to set service.endpoints.api.tls.cert" }}
  {{- end }}
  {{- "/cnom/certificates/api/manually_created_secret/key.pem" }}
{{- else if and .Values.ingress.enabled .Values.ingress.certificates.enabled .Values.ingress.tls.passthrough }}
  {{- "/cnom/certificates/api/certm/tls.key" }}
{{- else if and (not $endpoint.tls.disableSipTls) (.Capabilities.APIVersions.Has "siptls.sec.ericsson.com/v1/InternalCertificate") -}}
  {{- "/cnom/certificates/api/sip_tls/key.pem" }}
{{- else -}}
  {{- "" }}
{{- end -}}
{{- end }}

{{/*
TLS CA certificates for the yangStateData API
*/}}
{{- define "eric-cnom-server.yangStateData.tls-ca" -}}
  {{- $endpoint := .Values.service.endpoints.yangStateData -}}
  {{- $caPaths := (list) -}}
  {{- if and (not $endpoint.tls.disableSipTls) (.Capabilities.APIVersions.Has "siptls.sec.ericsson.com/v1/InternalUserCA") -}}
    {{- $caPaths = mustAppend $caPaths "/cnom/certificates/yangStateData/sip_tls/client-cacert.pem" }}
  {{- end -}}
  {{- range $ca := $endpoint.tls.ca -}}
    {{- $caPaths = default "client-cacertbundle.pem" $ca.bundle | printf "/cnom/certificates/yangStateData/%s/%s" $ca.name | mustAppend $caPaths -}}
  {{- end -}}
  {{- mustUniq $caPaths| join "," | quote }}
{{- end }}

{{/*
TLS certificates for the yangStateData API
*/}}
{{- define "eric-cnom-server.yangStateData.tls-certs" -}}
  {{- $endpoint := .Values.service.endpoints.yangStateData -}}
{{- if $endpoint.tls.cert -}}
  {{- if not $endpoint.tls.key }}
    {{ fail "When service.endpoints.yangStateData.tls.cert has been set, you also need to set service.endpoints.yangStateData.tls.key" }}
  {{- end }}
  {{- "/cnom/certificates/yangStateData/manually_created_secret/cert.pem" }}
{{- else if and (not $endpoint.tls.disableSipTls) (.Capabilities.APIVersions.Has "siptls.sec.ericsson.com/v1/InternalCertificate") -}}
  {{- "/cnom/certificates/yangStateData/sip_tls/cert.pem" }}
{{- else -}}
  {{- "" }}
{{- end -}}
{{- end }}

{{/*
TLS keys for the yangStateData API
*/}}
{{- define "eric-cnom-server.yangStateData.tls-keys" -}}
  {{- $endpoint := .Values.service.endpoints.yangStateData -}}
{{- if $endpoint.tls.key -}}
  {{- if not $endpoint.tls.cert }}
    {{ fail "When service.endpoints.yangStateData.tls.key has been set, you also need to set service.endpoints.yangStateData.tls.cert" }}
  {{- end }}
  {{- "/cnom/certificates/yangStateData/manually_created_secret/key.pem" }}
{{- else if and (not $endpoint.tls.disableSipTls) (.Capabilities.APIVersions.Has "siptls.sec.ericsson.com/v1/InternalCertificate") -}}
  {{- "/cnom/certificates/yangStateData/sip_tls/key.pem" }}
{{- else -}}
  {{- "" }}
{{- end -}}
{{- end }}

{{/*
Authentication providers
*/}}
{{- define "eric-cnom-server.authentication-providers" -}}
{{- $local := .Values.authentication.local.enabled | ternary "local" "" -}}
{{- $ldap := .Values.authentication.ldap.enabled | ternary "ldapADP" "" -}}
{{- $uniqueProviders := list $local $ldap | mustCompact -}}
{{- if and .Values.authentication.enabled (eq (len ($uniqueProviders)) 0) -}}
{{- "authentication.enabled is set to true, but no authentication providers have been configured. Please enable an authentication provider." | fail -}}
{{- else if and .Values.authentication.enabled (gt (len ($uniqueProviders)) 1) -}}
{{- printf "Only one authentication provider can be enabled. This limitation might be lifted in the future. Currently enabled providers: %s" $uniqueProviders | fail -}}
{{- else }}
{{- $uniqueProviders | join "," }}
{{- end }}
{{- end }}

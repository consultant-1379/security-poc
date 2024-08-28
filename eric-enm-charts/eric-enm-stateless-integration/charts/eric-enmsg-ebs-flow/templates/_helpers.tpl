{{/*
Dynamically calculate the number of replicas for the service group eric-enmsg-ebs-flow based on the Helm tags provided
*/}}
{{- define "eric-enmsg-ebs-flow.replicas" -}}
{{- if index .Values "global" "tags" -}}
  {{- if or .Values.global.tags.value_pack_ebs_ln .Values.global.tags.value_pack_ebs_m -}}
   {{- $replicas_ebs_ln := print (index .Values "replicas-eric-enmsg-ebs-flow" "ebs_ln") -}}
   {{- $replicas_ebs_m := print (index .Values "replicas-eric-enmsg-ebs-flow" "ebs_m") -}}
   {{- $replicas_ebs_ln_m := print (add $replicas_ebs_ln $replicas_ebs_m) -}}
   {{- if and .Values.global.tags.value_pack_ebs_ln (not .Values.global.tags.value_pack_ebs_m) -}}
     {{- print $replicas_ebs_ln -}}
   {{- end -}}
   {{- if and (.Values.global.tags.value_pack_ebs_m) (not .Values.global.tags.value_pack_ebs_ln) -}}
      {{- print $replicas_ebs_m -}}
   {{- end -}}
   {{- if and .Values.global.tags.value_pack_ebs_ln .Values.global.tags.value_pack_ebs_m -}}
      {{- print $replicas_ebs_ln_m -}}
   {{- end -}}
  {{- else -}}
    {{- print (index .Values "replicas-eric-enmsg-ebs-flow" "ebs_ln") -}}
  {{- end -}}
{{- else -}}
  {{- print (index .Values "replicas-eric-enmsg-ebs-flow" "ebs_ln") -}}
{{- end -}}
{{- end -}}

{{/*
Dynamically calculate the number of maxSkew/maxUnavailable/pdb for the service group eric-enmsg-ebs-flow based on the Helm tags provided
*/}}
{{- define "eric-enmsg-ebs-flow.maxunavailable" -}}
{{- if index .Values "global" "tags" -}}
  {{- if or .Values.global.tags.value_pack_ebs_ln .Values.global.tags.value_pack_ebs_m -}}
   {{- $replicas_ebs_ln := print (index .Values "replicas-eric-enmsg-ebs-flow" "ebs_ln") -}}
   {{- $replicas_ebs_m := print (index .Values "replicas-eric-enmsg-ebs-flow" "ebs_m") -}}
   {{- $replicas_ebs_ln_m := print (add $replicas_ebs_ln $replicas_ebs_m) -}}
   {{- $instances_spread_factor := (index .Values "ebs-flow-instances-spread-factor") -}}
   {{- if and .Values.global.tags.value_pack_ebs_ln (not .Values.global.tags.value_pack_ebs_m) -}}
     {{- div $replicas_ebs_ln $instances_spread_factor | default (index .Values "max-unavailable-eric-enmsg-ebs-flow") -}}
   {{- end -}}
   {{- if and (.Values.global.tags.value_pack_ebs_m) (not .Values.global.tags.value_pack_ebs_ln) -}}
     {{- div $replicas_ebs_m $instances_spread_factor | default (index .Values "max-unavailable-eric-enmsg-ebs-flow") -}}
   {{- end -}}
   {{- if and .Values.global.tags.value_pack_ebs_ln .Values.global.tags.value_pack_ebs_m -}}
     {{- div $replicas_ebs_ln_m $instances_spread_factor | default (index .Values "max-unavailable-eric-enmsg-ebs-flow") -}}
   {{- end -}}
  {{ else }}
   {{- print (index .Values "max-unavailable-eric-enmsg-ebs-flow") -}}
  {{- end -}}
{{- else -}}
  {{- print (index .Values "max-unavailable-eric-enmsg-ebs-flow") -}}
{{- end -}}
{{- end -}}
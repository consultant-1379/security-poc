{{/*
 Generate visinamingnb Instances Dynamically
*/}}
{{- define "{{.Chart.Name}}.podsname" -}}
    {{- $release := .Release.Namespace -}}
    {{- "visinamingnb" }}.{{ $release }}.status.podIP
{{- end -}}

{{/*
 Generate service that points to 2 pods under different deployment 
*/}}
{{- define "eric-enmsg-nb-alarm-irp-agent-corba.commonservice.tpl" -}}
apiVersion: v1
kind: Service
metadata:
{{ include "eric-enm-common-helmchart-library.metadata" . | indent 2 }}
spec:
  type: ClusterIP
  ports:
{{ tpl (.Files.Get "appconfig/commonsvcPorts.yaml") . | indent 4 }}
  selector:
    commonsvc: nbalarmirp
{{- end }}
{{- define "eric-enmsg-nb-alarm-irp-agent-corba.commonservice" -}}
{{- template "eric-enm-common-helmchart-library.util.merge" (append . "eric-enmsg-nb-alarm-irp-agent-corba.commonservice.tpl") -}}
{{- end -}}


{{/*
 overwriting the affinity of commonlibrary for nbalarmirp to used the label as commonsvc instead of app
*/}}
{{ define "eric-enmsg-nb-alarm-irp-agent-corba.affinity.tpl" -}}
{{- if .Values.affinity }}
affinity:
  podAntiAffinity:
    {{ if eq .Values.affinity "requiredDuringSchedulingIgnoredDuringExecution" }}
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: commonsvc
          operator: In
          values:
          - nbalarmirp
      topologyKey: "kubernetes.io/hostname"
    {{ else }}
    preferredDuringSchedulingIgnoredDuringExecution:
      - podAffinityTerm:
          labelSelector:
            matchExpressions:
            - key: commonsvc
              operator: In
              values:
              - nbalarmirp
          topologyKey: "kubernetes.io/hostname"
        weight: 1
    {{ end }}
{{- end }}
{{- end -}}




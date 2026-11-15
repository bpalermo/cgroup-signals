{{- define "cgroup-signals.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "cgroup-signals.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- /* A label value takes no "+": Flux adds the digest to the version as build metadata. */ -}}
{{- define "cgroup-signals.labels" -}}
{{ include "cgroup-signals.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- /*
The image: image.repository pinned by the digest stamped at package time, or,
when image.tag is set, by that tag (a mutable reference: for trying a build).
*/ -}}
{{- define "cgroup-signals.image" -}}
{{- if .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- else if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- fail "image.digest or image.tag is required" -}}
{{- end -}}
{{- end -}}

{{- /*
A PSI window that is not a multiple of 2 s needs CAP_SYS_RESOURCE, which
`privileged` covers; without it the kernel refuses the trigger and the process
exits at start-up, so refuse to render instead.
*/ -}}
{{- define "cgroup-signals.checkPSIWindow" -}}
{{- if and (not .Values.privileged) (ne (mod (int64 .Values.psi.windowUs) 2000000) 0) -}}
{{- fail (printf "psi.windowUs=%v is not a multiple of 2000000 (2 s): a trigger window like that needs CAP_SYS_RESOURCE; set privileged=true or use a multiple of 2 s" .Values.psi.windowUs) -}}
{{- end -}}
{{- end -}}

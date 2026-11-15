{{- define "bpftrace-debug.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "bpftrace-debug.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- /* A label value takes no "+": Flux adds the digest to the version as build metadata. */ -}}
{{- define "bpftrace-debug.labels" -}}
{{ include "bpftrace-debug.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "bpftrace-debug.image" -}}
{{- if .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- else if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- fail "image.digest or image.tag is required" -}}
{{- end -}}
{{- end -}}

{{- /* Refuse to render a pod that cannot do what was asked. */ -}}
{{- define "bpftrace-debug.check" -}}
{{- if not .Values.node -}}
{{- fail "node is required: the node to debug (--set node=<node name>)" -}}
{{- end -}}
{{- if and .Values.program .Values.programFile -}}
{{- fail "program and programFile are both set: choose one" -}}
{{- end -}}
{{- if lt (int64 .Values.activeDeadlineSeconds) 1 -}}
{{- fail "activeDeadlineSeconds must be at least 1: a debug pod always has a deadline" -}}
{{- end -}}
{{- end -}}

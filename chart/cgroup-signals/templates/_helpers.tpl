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

{{- define "cgroup-signals.runqueueName" -}}
{{- /* 54 + len("-runqueue") = 63: truncate the base, not the suffix */ -}}
{{- printf "%s-runqueue" (include "cgroup-signals.fullname" . | trunc 54 | trimSuffix "-") -}}
{{- end -}}

{{- /* Not the exporter's name: the two DaemonSets' selectors must not match each other's pods. */ -}}
{{- define "cgroup-signals.runqueueSelectorLabels" -}}
app.kubernetes.io/name: {{ printf "%s-runqueue" .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "cgroup-signals.runqueueLabels" -}}
{{ include "cgroup-signals.runqueueSelectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: runqueue
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
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

{{- /*
The run-queue exporter's histogram table holds 4095 cgroups and "other"; a
larger cap, or none, fails at start-up, so refuse to render instead.
*/ -}}
{{- define "cgroup-signals.checkRunqueue" -}}
{{- $n := int64 .Values.runqueue.maxTrackedCgroups -}}
{{- if or (lt $n 1) (gt $n 4095) -}}
{{- fail (printf "runqueue.maxTrackedCgroups=%v is outside 1..4095: the program's histogram table has 4095 slots" .Values.runqueue.maxTrackedCgroups) -}}
{{- end -}}
{{- end -}}

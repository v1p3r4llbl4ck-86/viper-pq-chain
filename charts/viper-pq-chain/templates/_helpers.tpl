{{/*
Expand the name of the chart.
*/}}
{{- define "viper-pq-chain.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully-qualified app name. Always release-prefixed unless fullnameOverride is set.
Truncates to 63 chars (k8s DNS-1123 limit).
*/}}
{{- define "viper-pq-chain.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label.
*/}}
{{- define "viper-pq-chain.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels — applied to every resource.
*/}}
{{- define "viper-pq-chain.labels" -}}
helm.sh/chart: {{ include "viper-pq-chain.chart" . }}
{{ include "viper-pq-chain.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
viper.pqchain.io/chain-id: {{ .Values.chain.id | quote }}
{{- end }}

{{/*
Selector labels — used in StatefulSet/Deployment selectors.
*/}}
{{- define "viper-pq-chain.selectorLabels" -}}
app.kubernetes.io/name: {{ include "viper-pq-chain.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Per-role full name. Suffix with the role identifier so multi-role releases
get distinct StatefulSets (e.g. release "viper", role "validator" →
"viper-pqcd-validator").
*/}}
{{- define "viper-pq-chain.roleName" -}}
{{- printf "%s-pqcd-%s" (include "viper-pq-chain.fullname" .ctx) .role | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Per-role selector labels — extends selectorLabels with role identity.
*/}}
{{- define "viper-pq-chain.roleSelectorLabels" -}}
{{ include "viper-pq-chain.selectorLabels" .ctx }}
viper.pqchain.io/role: {{ .role }}
viper.pqchain.io/component: pqcd
{{- end }}

{{/*
Per-role labels — full label set including version + role.
*/}}
{{- define "viper-pq-chain.roleLabels" -}}
{{ include "viper-pq-chain.labels" .ctx }}
viper.pqchain.io/role: {{ .role }}
viper.pqchain.io/component: pqcd
{{- end }}

{{/*
Notary full name + selector labels.
*/}}
{{- define "viper-pq-chain.notaryName" -}}
{{- printf "%s-notary" (include "viper-pq-chain.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "viper-pq-chain.notarySelectorLabels" -}}
{{ include "viper-pq-chain.selectorLabels" . }}
viper.pqchain.io/component: notary
{{- end }}

{{- define "viper-pq-chain.notaryLabels" -}}
{{ include "viper-pq-chain.labels" . }}
viper.pqchain.io/component: notary
{{- end }}

{{- define "viper-pq-chain.frontendName" -}}
{{- printf "%s-frontend" (include "viper-pq-chain.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "viper-pq-chain.frontendSelectorLabels" -}}
{{ include "viper-pq-chain.selectorLabels" . }}
viper.pqchain.io/component: frontend
{{- end }}

{{- define "viper-pq-chain.frontendLabels" -}}
{{ include "viper-pq-chain.labels" . }}
viper.pqchain.io/component: frontend
{{- end }}

{{/*
ServiceAccount name to use.
*/}}
{{- define "viper-pq-chain.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "viper-pq-chain.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference helper. Usage:
  image: {{ include "viper-pq-chain.image" (dict "ctx" $ "binary" "pqcd") }}

`binary` ∈ { "pqcd", "notary", "archivalSidecar" }.
*/}}
{{- define "viper-pq-chain.image" -}}
{{- $img := .ctx.Values.image -}}
{{- $tag := default .ctx.Chart.AppVersion (index $img.tags .binary) -}}
{{- $bin := .binary -}}
{{- if eq $bin "notary" }}{{ $bin = "viper-notary" }}{{ end -}}
{{- if eq $bin "archivalSidecar" }}{{ $bin = "viper-archival-sidecar" }}{{ end -}}
{{- printf "%s/%s/%s:%s" $img.registry $img.repository $bin $tag -}}
{{- end }}

{{/*
Merge `chainNode.common` defaults under a per-role config. Returns the
merged map. Usage:
  {{- $cfg := include "viper-pq-chain.roleConfig" (dict "ctx" $ "role" "validator") | fromYaml }}
*/}}
{{- define "viper-pq-chain.roleConfig" -}}
{{- $common := .ctx.Values.chainNode.common | default dict -}}
{{- $role := index .ctx.Values.chainNode .role | default dict -}}
{{- $merged := mustMergeOverwrite (deepCopy $common) $role -}}
{{- toYaml $merged -}}
{{- end }}

{{/*
List of enabled chain-node roles (validator, sentry, full, rpc, archive,
bootnode). Returns a comma-separated string for iteration.
*/}}
{{- define "viper-pq-chain.enabledRoles" -}}
{{- $out := list -}}
{{- range $r := list "validator" "sentry" "full" "rpc" "archive" "bootnode" -}}
  {{- $cfg := index $.Values.chainNode $r | default dict -}}
  {{- if $cfg.enabled -}}
    {{- $out = append $out $r -}}
  {{- end -}}
{{- end -}}
{{- join "," $out -}}
{{- end }}

{{/*
The first-enabled role's headless service hostname. Used by the notary
backend's auto-discovery of a chain RPC endpoint.
*/}}
{{- define "viper-pq-chain.firstChainNodeService" -}}
{{- $found := "" -}}
{{- range $r := list "rpc" "full" "sentry" "archive" "validator" -}}
  {{- $cfg := index $.Values.chainNode $r | default dict -}}
  {{- if and (eq $found "") $cfg.enabled -}}
    {{- $found = printf "%s-pqcd-%s" (include "viper-pq-chain.fullname" $) $r -}}
  {{- end -}}
{{- end -}}
{{- $found -}}
{{- end }}

{{- define "bifroest.name" -}}
  {{- default .Chart.Name .Values.nameOverride | trunc 54 | trimSuffix "-" -}}
{{- end -}}

{{- define "bifroest.fullname" -}}
  {{- if .Values.fullnameOverride -}}
    {{- .Values.fullnameOverride | trunc 54 | trimSuffix "-" -}}
  {{- else -}}
    {{- printf "%s-%s" .Release.Name (include "bifroest.name" .) | trunc 54 | trimSuffix "-" -}}
  {{- end -}}
{{- end -}}

{{- define "bifroest.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bifroest.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "bifroest.labels" -}}
{{ include "bifroest.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}

{{- define "bifroest.image" -}}
  {{- if .Values.image.digest -}}
    {{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
  {{- else -}}
    {{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
  {{- end -}}
{{- end -}}

{{- define "bifroest.configurationSource" -}}
  {{- if and (kindIs "string" .Values.configuration) (regexMatch "^(secret|configMap):" .Values.configuration) -}}
    {{- regexFind "^(secret|configMap)" .Values.configuration -}}
  {{- else -}}
    inline
  {{- end -}}
{{- end -}}

{{- define "bifroest.configurationName" -}}
  {{- $source := include "bifroest.configurationSource" . -}}
  {{- if eq $source "inline" -}}
    {{- include "bifroest.fullname" . -}}
  {{- else -}}
    {{- trimPrefix (printf "%s:" $source) .Values.configuration -}}
  {{- end -}}
{{- end -}}

{{- define "bifroest.configuration" -}}
  {{- if kindIs "map" .Values.configuration -}}
    {{- toYaml .Values.configuration -}}
  {{- else -}}
    {{- .Values.configuration -}}
  {{- end -}}
{{- end -}}

{{- define "bifroest.validate" -}}
  {{- if or (and .Values.service.ssh.enabled (eq (int .Values.service.ssh.targetPort) (int .Values.monitoring.port))) (and .Values.service.http.enabled (eq (int .Values.service.http.targetPort) (int .Values.monitoring.port))) -}}
    {{- fail "Services must not expose the private monitoring port" -}}
  {{- end -}}
  {{- if and .Values.service.ssh.enabled .Values.service.http.enabled (eq (int .Values.service.ssh.targetPort) (int .Values.service.http.targetPort)) -}}
    {{- fail "SSH and HTTP target ports must differ" -}}
  {{- end -}}
  {{- if and .Values.monitoring.prometheusAnnotations .Values.networkPolicy.enabled (not .Values.networkPolicy.monitoringPeers) -}}
    {{- fail "Prometheus scraping requires networkPolicy.monitoringPeers for the scraper" -}}
  {{- end -}}

  {{- $source := include "bifroest.configurationSource" . -}}
  {{- if ne $source "inline" -}}
    {{- $name := include "bifroest.configurationName" . -}}
    {{- if or (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $name)) -}}
      {{- fail "configuration reference must be secret:<name> or configMap:<name> with a valid Kubernetes object name" -}}
    {{- end -}}
  {{- else -}}
    {{- $config := include "bifroest.configuration" . | fromYaml -}}
    {{- if hasKey $config "Error" -}}
      {{- fail "configuration must contain a valid YAML object" -}}
    {{- end -}}
    {{- if not $config.flows -}}
      {{- fail "configuration.flows is required" -}}
    {{- end -}}

    {{- $monitoring := default dict $config.monitoring -}}
    {{- if not $monitoring.enabled -}}
      {{- fail "enable configuration.monitoring for the private probes" -}}
    {{- end -}}
    {{- if ne (toJson $monitoring.addresses) (toJson (list (printf ":%v" .Values.monitoring.port))) -}}
      {{- fail "configuration.monitoring.addresses must match monitoring.port on all Pod interfaces" -}}
    {{- end -}}
    {{- $tls := default dict $monitoring.tls -}}
    {{- if ne (eq .Values.monitoring.scheme "HTTPS") (default false $tls.enabled) -}}
      {{- fail "monitoring.scheme must match configuration.monitoring.tls.enabled" -}}
    {{- end -}}

    {{- $ssh := default dict $config.ssh -}}
    {{- if and .Values.service.ssh.enabled (not (has (printf ":%v" .Values.service.ssh.targetPort) (default list $ssh.addresses))) -}}
      {{- fail "configuration.ssh.addresses must include the SSH Service targetPort on all Pod interfaces" -}}
    {{- end -}}

    {{- $http := default dict $config.http -}}
    {{- $upstream := default dict $http.upstream -}}
    {{- $httpTls := default dict $http.tls -}}
    {{- if and (hasKey $httpTls "enabled") (not $httpTls.enabled) (ne (default "direct" $upstream.mode) "reverseProxy") -}}
      {{- fail "disabled HTTP TLS requires http.upstream.mode: reverseProxy" -}}
    {{- end -}}
    {{- if and (eq $upstream.mode "reverseProxy") (not $upstream.trustedPeers) -}}
      {{- fail "reverseProxy requires explicit http.upstream.trustedPeers" -}}
    {{- end -}}
    {{- if and .Values.service.http.enabled (not $http.enabled) -}}
      {{- fail "the HTTP Service requires configuration.http.enabled" -}}
    {{- end -}}
    {{- if and .Values.service.http.enabled (not (has (printf ":%v" .Values.service.http.targetPort) (default list $http.addresses))) -}}
      {{- fail "configuration.http.addresses must include the HTTP Service targetPort on all Pod interfaces" -}}
    {{- end -}}
    {{- if and .Values.ingress.enabled (ne $upstream.mode "reverseProxy") -}}
      {{- fail "HTTP Ingress requires http.upstream.mode: reverseProxy" -}}
    {{- end -}}
  {{- end -}}

  {{- if .Values.ingress.enabled -}}
    {{- if not .Values.service.http.enabled -}}
      {{- fail "Ingress requires service.http.enabled" -}}
    {{- end -}}
    {{- if ne .Values.service.http.type "ClusterIP" -}}
      {{- fail "Ingress requires a private ClusterIP HTTP Service" -}}
    {{- end -}}
    {{- if not .Values.ingress.host -}}
      {{- fail "ingress.host is required" -}}
    {{- end -}}
    {{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.httpPeers) -}}
      {{- fail "Ingress requires networkPolicy.httpPeers for the controller" -}}
    {{- end -}}
  {{- end -}}

  {{- if and .Values.podDisruptionBudget.enabled (le (int .Values.replicaCount) (int .Values.podDisruptionBudget.minAvailable)) -}}
    {{- fail "podDisruptionBudget.minAvailable must be below replicaCount" -}}
  {{- end -}}
  {{- if and (hasKey .Values.nodeSelector "kubernetes.io/os") (ne (index .Values.nodeSelector "kubernetes.io/os") "linux") -}}
    {{- fail "this chart requires Linux Pods" -}}
  {{- end -}}
{{- end -}}

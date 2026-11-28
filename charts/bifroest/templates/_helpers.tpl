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

{{- define "bifroest.watch" -}}
  {{- $watch := toString .Values.watch -}}
  {{- if has $watch (list "off" "false" "no" "0") -}}
    off
  {{- else if eq $watch "true" -}}
    preserve
  {{- else -}}
    {{- $watch -}}
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

{{/* Structural TLS selection only; security validation belongs to Bifröst. */}}
{{- define "bifroest.tlsSelection" -}}
  {{- $tls := .value -}}
  {{- $definitions := default dict .config.tls -}}
  {{- if not (kindIs "map" $definitions) -}}{{- fail "configuration.tls must be a mapping" -}}{{- end -}}
  {{- $automatic := or (and (not .present) .defaultWhenAbsent) (and .present (kindIs "string" $tls) (eq $tls "")) -}}
  {{- $enabled := and .present (not (kindIs "invalid" $tls)) -}}
  {{- $acme := false -}}
  {{- if $automatic -}}
    {{- $enabled = hasKey $definitions "default" -}}
    {{- if $enabled -}}{{- $tls = index $definitions "default" -}}{{- end -}}
  {{- else if and $enabled (kindIs "string" $tls) -}}
    {{- if not (hasKey $definitions $tls) -}}{{- fail "unknown TLS reference" -}}{{- end -}}
    {{- $tls = index $definitions $tls -}}
  {{- end -}}
  {{- if $enabled -}}
    {{- if not (kindIs "map" $tls) -}}{{- fail "TLS must select an inline mapping, not a reference chain" -}}{{- end -}}
  {{- else -}}
    {{- $tls = dict -}}
  {{- end -}}
  {{- if hasKey $tls "enabled" -}}
    {{- fail "TLS definitions do not accept enabled; set the listener's tls property to null to disable TLS" -}}
  {{- end -}}
  {{- if hasKey $tls "allowedNames" -}}{{- fail "TLS definitions contain unknown field allowedNames; set domains on the listener" -}}{{- end -}}
  {{- if and $enabled (hasKey $tls "acme") (not (kindIs "invalid" $tls.acme)) -}}
    {{- $automation := $tls.acme -}}
    {{- if not (kindIs "map" $automation) -}}{{- fail "TLS acme must be a mapping or null" -}}{{- end -}}
    {{- if hasKey $automation "enabled" -}}{{- fail "ACME does not accept enabled; omit acme or use null to disable it" -}}{{- end -}}
    {{- if not (and (kindIs "bool" $automation.acceptTerms) $automation.acceptTerms) -}}{{- fail "ACME requires acceptTerms: true" -}}{{- end -}}
    {{- $acme = true -}}
  {{- end -}}
  {{- dict "enabled" $enabled "acme" $acme | toJson -}}
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
    {{- if hasKey $config "tlsChallenge" -}}{{- fail "configuration contains unknown field tlsChallenge" -}}{{- end -}}
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
    {{- $tls := include "bifroest.tlsSelection" (dict "config" $config "value" $monitoring.tls "present" (hasKey $monitoring "tls") "defaultWhenAbsent" false) | fromJson -}}
    {{- if and $tls.enabled (not $monitoring.domains) -}}{{- fail "monitoring.domains is required when TLS is configured" -}}{{- end -}}
    {{- if ne (eq .Values.monitoring.scheme "HTTPS") $tls.enabled -}}
      {{- fail "monitoring.scheme must match whether configuration.monitoring.tls is configured" -}}
    {{- end -}}

    {{- $ssh := default dict $config.ssh -}}
    {{- if and .Values.service.ssh.enabled (not (has (printf ":%v" .Values.service.ssh.targetPort) (default list $ssh.addresses))) -}}
      {{- fail "configuration.ssh.addresses must include the SSH Service targetPort on all Pod interfaces" -}}
    {{- end -}}

    {{- $http := default dict $config.http -}}
    {{- $httpMode := false -}}
    {{- if hasKey $http "enabled" -}}{{- $httpMode = $http.enabled -}}{{- end -}}
    {{- $httpEnabled := eq (toJson $httpMode) "true" -}}
    {{- $alpnOnly := eq (toJson $httpMode) (toJson "acmeTlsAlpnOnly") -}}
    {{- if not (or (kindIs "bool" $httpMode) $alpnOnly) -}}{{- fail "http.enabled must be false, true or acmeTlsAlpnOnly" -}}{{- end -}}
    {{- $httpListener := or $httpEnabled $alpnOnly -}}
    {{- $upstream := default dict $http.upstream -}}
    {{- $httpTls := include "bifroest.tlsSelection" (dict "config" $config "value" $http.tls "present" (hasKey $http "tls") "defaultWhenAbsent" true) | fromJson -}}
    {{- if and $alpnOnly (or (not $httpTls.acme) (ne (default "direct" $upstream.mode) "direct")) -}}{{- fail "acmeTlsAlpnOnly requires ACME-enabled TLS and direct upstream mode" -}}{{- end -}}
    {{- if and $httpListener (not $http.domains) -}}{{- fail "http.domains is required when the listener is enabled" -}}{{- end -}}
    {{- if and $httpEnabled (not $httpTls.enabled) (ne (default "direct" $upstream.mode) "reverseProxy") -}}
      {{- fail "HTTP requires tls unless http.upstream.mode is reverseProxy" -}}
    {{- end -}}
    {{- if and (eq $upstream.mode "reverseProxy") (not $upstream.trustedPeers) -}}
      {{- fail "reverseProxy requires explicit http.upstream.trustedPeers" -}}
    {{- end -}}
    {{- if and .Values.service.http.enabled (not $httpListener) -}}
      {{- fail "the HTTP Service requires http.enabled: true or acmeTlsAlpnOnly" -}}
    {{- end -}}
    {{- if and .Values.service.http.enabled (not (has (printf ":%v" .Values.service.http.targetPort) (default list $http.addresses))) -}}
      {{- fail "configuration.http.addresses must include the HTTP Service targetPort on all Pod interfaces" -}}
    {{- end -}}
    {{- if and .Values.ingress.enabled (or (not $httpEnabled) (ne $upstream.mode "reverseProxy")) -}}
      {{- fail "HTTP Ingress requires http.upstream.mode: reverseProxy" -}}
    {{- end -}}
    {{- $acme := or (and $httpListener $httpTls.acme) (and $monitoring.enabled $tls.acme) -}}
    {{- if $acme -}}
      {{- if not (and $httpListener $httpTls.enabled) -}}{{- fail "active ACME requires an HTTP TLS listener with enabled true or acmeTlsAlpnOnly" -}}{{- end -}}
      {{- if ne (int .Values.replicaCount) 1 -}}{{- fail "direct ACME requires replicaCount: 1; use external certificate Secrets for multiple Pods" -}}{{- end -}}
      {{- if .Values.ingress.enabled -}}{{- fail "HTTP Ingress cannot forward TLS-ALPN-01; use TLS passthrough or external certificates" -}}{{- end -}}
      {{- if not .Values.service.http.enabled -}}{{- fail "direct ACME requires the HTTP Service for TCP 443" -}}{{- end -}}
      {{- $target := int .Values.service.http.targetPort -}}
      {{- if or (ne (int .Values.service.http.port) 443) (not .Values.service.http.publishNotReadyAddresses) -}}{{- fail "direct ACME requires Service port 443 and publishNotReadyAddresses" -}}{{- end -}}
      {{- if not (has (printf ":%v" $target) (default list $http.addresses)) -}}{{- fail "http.addresses must include the public TLS targetPort" -}}{{- end -}}
      {{- if and .Values.networkPolicy.enabled (not .Values.networkPolicy.httpPeers) -}}{{- fail "direct ACME requires networkPolicy.httpPeers for CA validation" -}}{{- end -}}
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

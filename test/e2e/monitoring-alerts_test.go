//go:build e2e

package e2e_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func monitoringSeries(name string, labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", key, labels[key]))
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}

func TestMonitoringDocumentedPrometheusAlerts(t *testing.T) {
	tool := monitoringTool(t, "BIFROEST_E2E_PROMTOOL", "promtool")
	root, err := findRepoRoot()
	require.NoError(t, err)
	dir := t.TempDir()
	rules := monitoringGuideRules(t, root)
	rulesPath := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0600))
	monitoringPromtool(t, tool, dir, "", "check", "rules", rulesPath)
	var documented struct {
		Groups []struct {
			Rules []struct {
				Alert string `yaml:"alert"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(rules), &documented))
	var names []string
	for _, group := range documented.Groups {
		for _, rule := range group.Rules {
			names = append(names, rule.Alert)
		}
	}
	base := map[string]string{"job": "bifroest", "instance": "qa:9090"}
	with := func(extra map[string]string) map[string]string {
		labels := make(map[string]string)
		for k, v := range base {
			labels[k] = v
		}
		for k, v := range extra {
			labels[k] = v
		}
		return labels
	}
	auditLabels := with(map[string]string{"auditlog": "operations"})
	flowLabels := with(map[string]string{"auditlog": "operations", "authorization": "login", "environment": "sandbox", "flow": "shell"})
	requestLabels := func(status string) map[string]string {
		return with(map[string]string{"status": status, "route": "login/password", "method": "POST", "flow": "shell"})
	}
	type fixture struct {
		name, healthy string
		labels        map[string]string
	}
	inputs := []fixture{
		{"up", "1+0x30", base},
		{"bifroest_auditlog_disabled", "0+0x30", auditLabels},
		{"bifroest_recording_spool_bytes", "100+0x30", auditLabels},
		{"bifroest_recording_spool_limit_bytes", "1000+0x30", auditLabels},
		{"bifroest_recording_spool_accounting_valid", "1+0x30", auditLabels},
		{"bifroest_remote_delivery_pending_observed_seconds", "0+0x30", with(map[string]string{"auditlog": "operations", "target": "archive", "kind": "audit"})},
		{"bifroest_cleanup_problems", "0+0x30", flowLabels},
		{"bifroest_cleanup_last_run_success", "1+0x30", with(map[string]string{"auditlog": "operations", "authorization": "login", "environment": "sandbox", "flow": "shell", "operation": "housekeeping"})},
		{"bifroest_auditlog_available_bytes", "1000+0x30", auditLabels},
		{"bifroest_auditlog_minimum_free_bytes", "100+0x30", auditLabels},
		{"bifroest_auditlog_space_observation_valid", "1+0x30", auditLabels},
		{"bifroest_auditlog_space_observation_timestamp_seconds", "0+60x30", auditLabels},
		{"bifroest_http_tls_certificate_expiration_timestamp_seconds", "10000000+0x30", with(map[string]string{"domain": "app.example.org"})},
		{"bifroest_http_requests_total", "0+100x30", requestLabels("200")},
		{"bifroest_http_requests_total", "0+0x30", requestLabels("500")},
	}
	type alarm struct {
		name, metric, bad string
		labels            map[string]string
	}
	alarms := []alarm{
		{"BifroestMetricsUnavailable", "up", "0+0x30", base},
		{"BifroestAuditlogDisabled", "bifroest_auditlog_disabled", "1+0x30", auditLabels},
		{"BifroestRecordingSpoolPressure", "bifroest_recording_spool_bytes", "900+0x30", auditLabels},
		{"BifroestRecordingAccountingUnavailable", "bifroest_recording_spool_accounting_valid", "0+0x30", auditLabels},
		{"BifroestDeliveryStalled", "bifroest_remote_delivery_pending_observed_seconds", "400+0x30", inputs[5].labels},
		{"BifroestCleanupFailing", "bifroest_cleanup_problems", "1+0x30", flowLabels},
		{"BifroestJournalSpaceLow", "bifroest_auditlog_available_bytes", "150+0x30", auditLabels},
		{"BifroestHttpCertificateExpiring", "bifroest_http_tls_certificate_expiration_timestamp_seconds", "3600+0x30", inputs[12].labels},
		{"BifroestHttpServerErrors", "http_500", "0+20x30", base},
	}
	var covered []string
	for _, alarm := range alarms {
		covered = append(covered, alarm.name)
	}
	require.ElementsMatch(t, names, covered, "each documented alert must have a firing test")
	var tests []any
	add := func(name string, overrides map[string]string, at string, firing *alarm) {
		var series []any
		for _, input := range inputs {
			key := input.name
			if key == "bifroest_http_requests_total" {
				key = "http_" + input.labels["status"]
			}
			values := input.healthy
			if override, ok := overrides[key]; ok {
				values = override
			}
			series = append(series, map[string]any{"series": monitoringSeries(input.name, input.labels), "values": values})
		}
		var checks []any
		for _, alert := range names {
			expected := []any{}
			if firing != nil && firing.name == alert {
				expected = append(expected, map[string]any{"exp_labels": firing.labels, "exp_annotations": map[string]string{}})
			}
			checks = append(checks, map[string]any{"eval_time": at, "alertname": alert, "exp_alerts": expected})
		}
		tests = append(tests, map[string]any{"name": name, "interval": "1m", "input_series": series, "alert_rule_test": checks})
	}
	add("healthy instance", nil, "16m", nil)
	for _, alarm := range alarms {
		add(alarm.name, map[string]string{alarm.metric: alarm.bad}, "16m", &alarm)
	}
	add("short scrape interruption must not fire", map[string]string{"up": "0+0x30"}, "1m", nil)
	add("invalid journal observation must not report low space", map[string]string{"bifroest_auditlog_available_bytes": "150+0x30", "bifroest_auditlog_space_observation_valid": "0+0x30"}, "16m", nil)
	add("stale journal observation must not report low space", map[string]string{"bifroest_auditlog_available_bytes": "150+0x30", "bifroest_auditlog_space_observation_timestamp_seconds": "0+0x30"}, "16m", nil)
	add("idle HTTP must not report a server error ratio", map[string]string{"http_200": "0+0x30"}, "16m", nil)
	add("HTTP error ratio below five percent must not fire", map[string]string{"http_500": "0+5x30"}, "16m", nil)
	testsPath := filepath.Join(dir, "rules.test.yaml")
	monitoringJSONFile(t, testsPath, map[string]any{"rule_files": []string{rulesPath}, "evaluation_interval": "1m", "tests": tests})
	monitoringPromtool(t, tool, dir, "", "test", "rules", testsPath)
	t.Logf("validated all %d documented alerts with %d firing/negative scenarios", len(names), len(tests))
}

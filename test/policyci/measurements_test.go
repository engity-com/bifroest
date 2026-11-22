package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const measuredJSON = `{"durationSeconds":0.004,"apiVersion":"bifroest.engity.org/testing/v1alpha1","scope":"post-authentication/session-target","packages":[{"durationSeconds":0.003,"name":"fixture"}],"suites":[{"durationSeconds":0.002,"name":"suite","source":"case_bftest.lua","package":"fixture"}],"results":[{"durationSeconds":0.001,"name":"case","source":"case_bftest.lua","package":"fixture","status":"passed"}]}`

const measuredXML = `<testsuites time="0.004000000"><testsuite name="suite" time="0.002000000"><properties><property name="source" value="case_bftest.lua"/><property name="package" value="fixture"/></properties><testcase name="case" file="case_bftest.lua" time="0.001000000"/></testsuite></testsuites>`

func TestMeasurementValidationRequiresPositiveMeasuredDurationsAndPackages(t *testing.T) {
	check := func(t *testing.T, jsonText, xmlText string) error {
		t.Helper()
		folder := t.TempDir()
		jsonPath, xmlPath := filepath.Join(folder, "report.json"), filepath.Join(folder, "report.xml")
		require.NoError(t, os.WriteFile(jsonPath, []byte(jsonText), 0600))
		require.NoError(t, os.WriteFile(xmlPath, []byte(xmlText), 0600))
		return validateMeasurements(jsonPath, xmlPath)
	}
	require.NoError(t, check(t, measuredJSON, measuredXML))
	for _, timing := range []struct{ name, value string }{
		{"run", "0.004"}, {"package", "0.003"}, {"suite", "0.002"}, {"testcase", "0.001"},
	} {
		for _, value := range []string{"0", "-1", "null", "missing"} {
			t.Run("JSON/"+timing.name+"/"+value, func(t *testing.T) {
				token := `"durationSeconds":` + timing.value
				text := strings.Replace(measuredJSON, token, `"durationSeconds":`+value, 1)
				if value == "missing" {
					text = strings.Replace(measuredJSON, token+",", "", 1)
				}
				require.Error(t, check(t, text, measuredXML))
			})
		}
	}
	for _, timing := range []struct{ name, value string }{
		{"run", "0.004000000"}, {"suite", "0.002000000"}, {"testcase", "0.001000000"},
	} {
		for _, value := range []string{"0", "-1", "NaN", "+Inf", "", "0.123"} {
			t.Run("JUnit/"+timing.name+"/"+value, func(t *testing.T) {
				text := strings.Replace(measuredXML, `time="`+timing.value+`"`, `time="`+value+`"`, 1)
				require.Error(t, check(t, measuredJSON, text))
			})
		}
	}
	for _, replacement := range []struct{ name, before, after string }{
		{"empty-package-name", `"name":"fixture"`, `"name":""`},
		{"unknown-suite-package", `"package":"fixture"`, `"package":"other"`},
		{"unknown-testcase-package", `"package":"fixture","status"`, `"package":"other","status"`},
		{"lost-JUnit-package", `name="package" value="fixture"`, `name="package" value="other"`},
	} {
		t.Run(replacement.name, func(t *testing.T) {
			text := strings.Replace(measuredJSON, replacement.before, replacement.after, 1)
			xmlText := strings.Replace(measuredXML, replacement.before, replacement.after, 1)
			require.Error(t, check(t, text, xmlText))
		})
	}
}

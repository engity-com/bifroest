package test

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShortRunnerPathsRetainMeasuredDurations(t *testing.T) {
	source := inlineSuite("short", `t:IsEqual(true,true)`)
	for _, test := range []struct {
		name, source string
		options      Options
		code, suites int
	}{
		{name: "executed", source: source, suites: 1},
		{name: "platform-excluded", source: strings.Replace(source, `name="short",`, `name="short",platform={os={}},`, 1), code: 2, suites: 1},
		{name: "name-filtered", source: source, options: Options{Includes: []string{"^none/"}}, code: 2, suites: 1},
		{name: "load-error", source: "suite {", code: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "short_bftest.lua")
			writeInput(t, path, test.source)
			for range 16 {
				report := RunPaths(t.Context(), []string{path}, test.options)
				require.Equal(t, test.code, report.ExitCode())
				require.Len(t, report.Suites, test.suites)
				require.Len(t, report.Packages, 1)
				require.Positive(t, report.DurationSeconds)
				require.Positive(t, report.Packages[0].DurationSeconds)
				for _, suite := range report.Suites {
					require.Positive(t, suite.DurationSeconds)
				}
				for _, result := range report.Results {
					require.Positive(t, result.DurationSeconds)
				}
				var raw bytes.Buffer
				require.NoError(t, report.WriteJSON(&raw))
				var decoded Report
				require.NoError(t, json.Unmarshal(raw.Bytes(), &decoded))
				require.Equal(t, report.DurationSeconds, decoded.DurationSeconds)
				require.Equal(t, report.Packages, decoded.Packages)
				require.Equal(t, report.Suites, decoded.Suites)
				require.Equal(t, report.Results, decoded.Results)
				parsed, _ := readJUnit(t, report)
				seconds, err := strconv.ParseFloat(parsed.Time, 64)
				require.NoError(t, err)
				require.InDelta(t, report.DurationSeconds, seconds, 1e-9)
				for _, suite := range parsed.Suites {
					if suite.Name == "bifroest.policytest.runner" {
						continue
					}
					seconds, err := strconv.ParseFloat(suite.Time, 64)
					require.NoError(t, err)
					require.InDelta(t, report.Suites[0].DurationSeconds, seconds, 1e-9)
				}
			}
		})
	}
}

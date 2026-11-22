package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const sampleJSON = `{"apiVersion":"bifroest.engity.org/testing/v1alpha1","scope":"post-authentication/session-target","results":[{"suite":"example","source":"red_bftest.lua","name":"red","status":"failed","assertions":1,"failures":[{"line":7,"expected":"true","actual":"false","reason":"why"}]}],"summary":{"passed":0,"failed":1,"skipped":0,"errors":0}}`

const sampleXML = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="1" failures="1" errors="0" skipped="0">
<testsuite name="example" tests="1" failures="1" errors="0" skipped="0">
<properties><property name="apiVersion" value="bifroest.engity.org/testing/v1alpha1"/><property name="scope" value="post-authentication/session-target"/><property name="authenticationAssumed" value="true"/><property name="source" value="red_bftest.lua"/></properties>
<testcase name="red" classname="example" file="red_bftest.lua" line="7" assertions="1"><failure type="assertion" message="1 assertion failed">red_bftest.lua:7: expected true, actual false; reason &#34;why&#34;</failure></testcase>
</testsuite></testsuites>`

func reportFiles(t *testing.T, rawJSON, rawXML string) (string, string) {
	t.Helper()
	folder := t.TempDir()
	j, x := filepath.Join(folder, "report.json"), filepath.Join(folder, "report.xml")
	require.NoError(t, os.WriteFile(j, []byte(rawJSON), 0600))
	require.NoError(t, os.WriteFile(x, []byte(rawXML), 0600))
	return j, x
}

func TestIndependentReportValidationRejectsInconsistentOutcomes(t *testing.T) {
	for _, test := range []struct {
		name, json, xml string
	}{
		{"JSON summary", strings.Replace(sampleJSON, `"failed":1`, `"failed":0`, 1), sampleXML},
		{"JSON assertion count", strings.Replace(sampleJSON, `"assertions":1`, `"assertions":0`, 1), sampleXML},
		{"JSON unknown status", strings.Replace(sampleJSON, `"failed"`, `"unknown"`, 1), sampleXML},
		{"JSON source", strings.ReplaceAll(sampleJSON, "red_bftest.lua", ""), sampleXML},
		{"XML parse", sampleJSON, "<testsuites>"},
		{"XML root", sampleJSON, strings.ReplaceAll(sampleXML, "testsuites", "other")},
		{"XML total", sampleJSON, strings.Replace(sampleXML, `tests="1"`, `tests="2"`, 1)},
		{"XML suite total", sampleJSON, strings.ReplaceAll(sampleXML, `failures="1"`, `failures="2"`)},
		{"XML offline metadata", sampleJSON, strings.Replace(sampleXML, `value="true"`, `value="false"`, 1)},
		{"XML missing case", sampleJSON, strings.Replace(sampleXML, `name="red"`, `name="different"`, 1)},
		{"XML duplicated case", sampleJSON, strings.Replace(sampleXML, "</testcase>", "</testcase><testcase name=\"red\"/>", 1)},
		{"XML multiple status nodes", sampleJSON, strings.Replace(sampleXML, "</failure>", "</failure><error/>", 1)},
		{"XML failure category", sampleJSON, strings.Replace(sampleXML, `type="assertion"`, `type="config"`, 1)},
		{"XML assertion line", sampleJSON, strings.Replace(sampleXML, `line="7"`, `line="8"`, 1)},
		{"XML assertion details", sampleJSON, strings.Replace(sampleXML, "actual false", "actual unknown", 1)},
		{"XML source group", sampleJSON, strings.Replace(sampleXML, `file="red_bftest.lua"`, `file="different_bftest.lua"`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			j, x := reportFiles(t, test.json, test.xml)
			require.Error(t, validateReports(j, x, counts{Failed: 1}))
		})
	}
	j, x := reportFiles(t, sampleJSON, sampleXML)
	require.NoError(t, validateReports(j, x, counts{Failed: 1}))
}

func TestEmptySelectionRequiresSyntheticJUnitError(t *testing.T) {
	rawJSON := `{"apiVersion":"bifroest.engity.org/testing/v1alpha1","scope":"post-authentication/session-target","results":null,"summary":{"passed":0,"failed":0,"skipped":0,"errors":1}}`
	rawXML := strings.ReplaceAll(sampleXML, `failures="1"`, `failures="0"`)
	rawXML = strings.ReplaceAll(rawXML, `errors="0"`, `errors="1"`)
	rawXML = strings.ReplaceAll(rawXML, `name="example"`, `name="bifroest.policytest.runner"`)
	rawXML = strings.ReplaceAll(rawXML, `<property name="source" value="red_bftest.lua"/>`, "")
	start := strings.Index(rawXML, "<testcase")
	end := strings.Index(rawXML, "</testcase>") + len("</testcase>")
	rawXML = rawXML[:start] + `<testcase name="no-tests-selected" classname="bifroest.policytest.runner" assertions="0"><error type="system" message="no tests selected"/></testcase>` + rawXML[end:]
	j, x := reportFiles(t, rawJSON, rawXML)
	require.NoError(t, validateReports(j, x, counts{Errors: 1}))
	require.NoError(t, os.WriteFile(x, []byte(strings.Replace(rawXML, `<error type="system" message="no tests selected"/>`, "", 1)), 0600))
	require.Error(t, validateReports(j, x, counts{Errors: 1}))
}

func TestReportFailureAndTextChecksCannotHideFailures(t *testing.T) {
	folder := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(folder, "blocked"), []byte("sentinel"), 0600))
	rawJSON := fmt.Sprintf(`{"apiVersion":"%s","scope":"%s","summary":{"passed":1}}`, apiVersion, scope)
	require.NoError(t, os.WriteFile(filepath.Join(folder, "report.json"), []byte(rawJSON), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(folder, "cli.stderr.txt"), []byte("cannot write offline policy test report blocked: mkdir blocked: file exists"), 0600))
	require.NoError(t, validateReportFailure(folder, []byte("sentinel")))
	require.Error(t, validateReportFailure(folder, []byte("different")))
	require.NoError(t, os.WriteFile(filepath.Join(folder, "cli.stderr.txt"), []byte("cannot write offline policy test report"), 0600))
	require.Error(t, validateReportFailure(folder, []byte("sentinel")))
	require.NoError(t, os.WriteFile(filepath.Join(folder, "cli.stdout.txt"), []byte("RESULT: 0 PASSED, 1 FAILED, 0 SKIPPED\n"), 0600))
	require.NoError(t, validateText(folder, counts{Failed: 1}))
	require.Error(t, validateText(folder, counts{Passed: 1}))
}

func TestDeliberatelyRedLocationsUseEachPhysicalPlatformFixture(t *testing.T) {
	for _, test := range []struct {
		variant string
		line    int
	}{{"unix", 19}, {"windows", 18}} {
		t.Run(test.variant, func(t *testing.T) {
			raw := fmt.Sprintf(`{"apiVersion":"%s","scope":"%s","results":[{"source":"red-%s_bftest.lua","name":"wrong-target-contract","failures":[{"line":%d,"expected":"\"not-alice\"","reason":"Deliberately red smoke test"}]}]}`, apiVersion, scope, test.variant, test.line)
			path, _ := reportFiles(t, raw, "")
			require.NoError(t, validateRed(path))
			raw = strings.Replace(raw, fmt.Sprintf(`"line":%d`, test.line), `"line":999`, 1)
			require.NoError(t, os.WriteFile(path, []byte(raw), 0600))
			require.Error(t, validateRed(path))
		})
	}
}

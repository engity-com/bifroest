package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func jsonLine(t *testing.T, e event) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\r\n"
}

func analyzeEvents(t *testing.T, events ...event) (*analyzer, *bytes.Buffer) {
	t.Helper()
	var human bytes.Buffer
	a := newAnalyzer(&human)
	for _, e := range events {
		line := jsonLine(t, e)
		// Split even CRLF and UTF-8 arbitrarily, as os/exec may do.
		for len(line) > 0 {
			n := min(len(line), 7)
			if _, err := a.Write([]byte(line[:n])); err != nil {
				t.Fatal(err)
			}
			line = line[n:]
		}
	}
	a.finish()
	return a, &human
}

func TestTimingCacheAndSubtests(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(n int) time.Time { return start.Add(time.Duration(n) * time.Second) }
	a, human := analyzeEvents(t,
		event{Time: at(0), Action: "start", Package: "one"},
		event{Time: at(0), Action: "run", Package: "one", Test: "TestParent"},
		event{Time: at(1), Action: "start", Package: "two"},
		event{Time: at(1), Action: "pass", Package: "one", Test: "TestParent/sub", Elapsed: seconds(0.5)},
		event{Time: at(2), Action: "pass", Package: "one", Test: "TestParent", Elapsed: seconds(1.2)},
		event{Time: at(2), Action: "run", Package: "one", Test: "TestParent"},
		event{Time: at(3), Action: "pass", Package: "one", Test: "TestParent", Elapsed: seconds(0.8)},
		event{Time: at(3), Action: "pass", Package: "one", Elapsed: seconds(3)},
		event{Time: at(4), Action: "pass", Package: "two", Test: "TestOther", Elapsed: seconds(2)},
		event{Time: at(4), Action: "pass", Package: "two", Elapsed: seconds(3)},
		event{Time: at(4), Action: "start", Package: "cached"},
		event{Time: at(4), Action: "pass", Package: "cached", Test: "TestHistorical", Elapsed: seconds(99)},
		event{Time: at(4), Action: "output", Package: "cached", Output: "ok  \tcached\t(cached)\n"},
		event{Time: at(5), Action: "pass", Package: "cached", Elapsed: seconds(99)},
	)
	a.commandStart, a.commandEnd = at(-1), at(5)
	r := report{WallSeconds: seconds(6)}
	a.fill(&r, nil)
	if r.Status != "pass" || !r.Complete {
		t.Fatalf("unexpected result: %+v", r)
	}
	if r.Timing.UncachedTopLevelTestElapsedSeconds == nil || *r.Timing.UncachedTopLevelTestElapsedSeconds != 4 {
		t.Fatalf("nested/cache double counting: %+v", r.Timing)
	}
	if r.Timing.UncachedPackageElapsedSeconds == nil || *r.Timing.UncachedPackageElapsedSeconds != 6 {
		t.Fatalf("cached package counted: %+v", r.Timing)
	}
	if *r.Timing.PackageIntervalUnionSeconds != 4 || *r.Timing.OutsidePackageEstimateSeconds != 2 {
		t.Fatalf("interval calculation: %+v", r.Timing)
	}
	if r.Cases[0].Package != "one" || r.Cases[0].Runs != 2 || *r.Cases[0].ElapsedSeconds != 2 {
		t.Fatalf("aggregation/tie ordering: %+v", r.Cases)
	}
	if c := r.Cases[len(r.Cases)-1]; !c.Cached || c.Test != "TestHistorical" {
		t.Fatalf("cached sorting: %+v", r.Cases)
	}
	if !strings.Contains(human.String(), "(cached)") {
		t.Fatal("human output missing")
	}
}

func TestInvalidUnknownAndIncompleteStreams(t *testing.T) {
	good := "{\"Action\":\"start\",\"Package\":\"p\"}\n{\"Action\":\"pass\",\"Package\":\"p\",\"Elapsed\":0}\n"
	for _, tc := range []struct {
		name, input              string
		invalid, unknown, builds int
		status                   string
	}{
		{"empty", "", 0, 0, 0, "incomplete"},
		{"truncated", good + "{\"Action\":", 1, 0, 0, "incomplete"},
		{"non-json", "build diagnostic\r\n" + good, 1, 0, 0, "incomplete"},
		{"unknown", good + "{\"Action\":\"future-action\",\"Package\":\"p\",\"Output\":\"future output\"}\n", 0, 1, 0, "incomplete"},
		{"invalid-shape", good + "{}\n", 1, 0, 0, "incomplete"},
		{"negative-time", good + "{\"Action\":\"pass\",\"Package\":\"p\",\"Elapsed\":-1}\n", 1, 0, 0, "incomplete"},
		{"impossible-time", good + "{\"Action\":\"pass\",\"Package\":\"p\",\"Elapsed\":1e308}\n", 1, 0, 0, "incomplete"},
		{"no-terminal", "{\"Action\":\"start\",\"Package\":\"p\"}\n", 0, 0, 0, "incomplete"},
		{"no-start", "{\"Action\":\"pass\",\"Package\":\"p\"}\n", 0, 0, 0, "incomplete"},
		{"pending-test", "{\"Action\":\"run\",\"Package\":\"p\",\"Test\":\"TestPending\"}\n" + good, 0, 0, 0, "incomplete"},
		{"build-failure", "{\"Action\":\"build-output\",\"ImportPath\":\"p\",\"Output\":\"build error\"}\n{\"Action\":\"build-fail\",\"ImportPath\":\"p\"}\n", 0, 0, 1, "fail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var human bytes.Buffer
			a := newAnalyzer(&human)
			if _, err := io.Copy(a, strings.NewReader(tc.input)); err != nil {
				t.Fatal(err)
			}
			a.finish()
			r := report{}
			a.fill(&r, nil)
			if r.Status != tc.status || r.InvalidRecords != tc.invalid || r.UnknownEvents != tc.unknown || r.BuildFailures != tc.builds || r.Complete {
				t.Fatalf("unexpected report: %+v", r)
			}
			if tc.unknown > 0 && !strings.Contains(human.String(), "future output") {
				t.Fatal("unknown output was lost")
			}
		})
	}
}

func TestOversizedRecordIsBoundedAndRawDiagnosticsSurvive(t *testing.T) {
	var human bytes.Buffer
	a := newAnalyzer(&human)
	chunk := strings.Repeat("x", 8192)
	for i := 0; i < 3*maxEventBytes/len(chunk); i++ {
		if _, err := io.WriteString(a, chunk); err != nil {
			t.Fatal(err)
		}
		if cap(a.line) > 2*maxEventBytes {
			t.Fatalf("unbounded line buffer: %d", cap(a.line))
		}
	}
	io.WriteString(a, "\n{\"Action\":\"start\",\"Package\":\"p\"}\r\n{\"Action\":\"pass\",\"Package\":\"p\"}")
	a.finish()
	if a.invalid != 1 || len(a.packages) != 1 {
		t.Fatalf("did not recover: %+v", a)
	}
	if human.Len() != 3*maxEventBytes+1 {
		t.Fatalf("lost diagnostic output: %d", human.Len())
	}
}

func TestBaselineMeansNewCasesAndNoPerformanceGate(t *testing.T) {
	old := []caseMetric{
		{Package: "p", Test: "TestRepeated", Status: "pass", Runs: 2, TimedRuns: 2, ElapsedSeconds: seconds(4)},
		{Package: "p", Test: "TestZero", Status: "pass", Runs: 1, TimedRuns: 1, ElapsedSeconds: seconds(0)},
		{Package: "p", Test: "TestCached", Status: "pass", Runs: 1, TimedRuns: 1, ElapsedSeconds: seconds(10), Cached: true},
	}
	current := []caseMetric{
		{Package: "p", Test: "TestRepeated", Status: "pass", Runs: 1, TimedRuns: 1, ElapsedSeconds: seconds(3)},
		{Package: "p", Test: "TestZero", Status: "pass", Runs: 1, TimedRuns: 1, ElapsedSeconds: seconds(5)},
		{Package: "p", Test: "TestNew", Status: "pass", Runs: 1, TimedRuns: 1, ElapsedSeconds: seconds(9)},
		{Package: "p", Test: "TestCached", Status: "pass", Runs: 1, TimedRuns: 1, ElapsedSeconds: seconds(20)},
		{Package: "p", Test: "TestSkip", Status: "skip", Runs: 1, TimedRuns: 1, ElapsedSeconds: seconds(40)},
	}
	got := compare(current, old)
	if len(got) != 4 || got[0].Test != "TestZero" || got[0].DeltaPercent != nil {
		t.Fatalf("zero baseline/sort: %+v", got)
	}
	if got[1].Test != "TestRepeated" || *got[1].DeltaSeconds != 1 || *got[1].DeltaPercent != 50 {
		t.Fatalf("mean comparison: %+v", got[1])
	}
	if !got[2].New || got[2].Test != "TestCached" || !got[3].New {
		t.Fatalf("new comparable cases: %+v", got)
	}
	a, _ := analyzeEvents(t, event{Action: "start", Package: "p"}, event{Action: "pass", Package: "p", Test: "TestRepeated", Elapsed: seconds(1000)}, event{Action: "pass", Package: "p"})
	r := report{}
	a.fill(&r, &report{Cases: old, Status: "fail", Complete: false})
	if r.Status != "pass" || !r.Complete {
		t.Fatalf("baseline/performance warning became a gate: %+v", r)
	}
}

func TestMarkdownTopAndEscaping(t *testing.T) {
	bad := "<script>|`[click](https://example.invalid)\r\n**fake**"
	r := report{Status: "pass", Complete: true, Cases: []caseMetric{
		{Package: "p", Test: bad, ElapsedSeconds: seconds(1)},
		{Package: "p", Test: "SHOULD_NOT_APPEAR", ElapsedSeconds: seconds(0.1)},
	}}
	got := markdown(&r, 1)
	if strings.Contains(got, "<script>") || strings.Contains(got, "[click]") || strings.Contains(got, "**fake**") || strings.Contains(got, "SHOULD_NOT_APPEAR") || !strings.Contains(got, "&lt;script&gt;&#124;&#96;") {
		t.Fatalf("unsafe/unbounded Markdown:\n%s", got)
	}
	if !strings.Contains(got, "n/a") {
		t.Fatal("missing data was rendered as zero")
	}
}

func TestMissingTimingsAreNotZeroOrComparable(t *testing.T) {
	a, _ := analyzeEvents(t,
		event{Action: "start", Package: "p"},
		event{Action: "pass", Package: "p", Test: "TestPartial", Elapsed: seconds(2)},
		event{Action: "pass", Package: "p", Test: "TestPartial"},
		event{Action: "pass", Package: "p"},
	)
	r := report{}
	a.fill(&r, nil)
	if r.Timing.UncachedPackageElapsedSeconds != nil || r.Cases[0].TimedRuns != 1 || r.Cases[0].Runs != 2 {
		t.Fatalf("missing duration invented: %+v", r)
	}
	if len(compare(r.Cases, nil)) != 0 {
		t.Fatal("partially timed case used as a full baseline comparison")
	}
	a, _ = analyzeEvents(t, event{Action: "start", Package: "p"}, event{Action: "pass", Package: "p", Test: "TestNoDuration"}, event{Action: "pass", Package: "p"})
	r = report{}
	a.fill(&r, nil)
	if r.Cases[0].ElapsedSeconds != nil || r.Timing.UncachedTopLevelTestElapsedSeconds != nil {
		t.Fatal("missing duration fabricated as zero")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestHumanWriteError(t *testing.T) {
	a := newAnalyzer(brokenWriter{})
	_, err := io.WriteString(a, "{\"Action\":\"output\",\"Package\":\"p\",\"Output\":\"hello\"}\n")
	if err == nil {
		t.Fatal("output error ignored")
	}
	a.finish()
	r := report{}
	a.fill(&r, nil)
	if r.Complete || r.Status == "pass" {
		t.Fatal("output failure reported as pass")
	}
}

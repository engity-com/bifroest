package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxEventBytes = 1024 * 1024

type event struct {
	Time       time.Time
	Action     string
	Package    string
	ImportPath string
	Test       string
	Elapsed    *float64
	Output     string
}

type caseMetric struct {
	Package        string   `json:"package"`
	Test           string   `json:"test"`
	Status         string   `json:"status"`
	ElapsedSeconds *float64 `json:"elapsed_seconds,omitempty"`
	Runs           int      `json:"runs"`
	TimedRuns      int      `json:"timed_runs"`
	Cached         bool     `json:"cached"`
	Nested         bool     `json:"nested"`
}

type packageMetric struct {
	Package        string   `json:"package"`
	Status         string   `json:"status"`
	ElapsedSeconds *float64 `json:"elapsed_seconds,omitempty"`
	Cached         bool     `json:"cached"`
	Cases          int      `json:"cases"`
}

type comparison struct {
	Package             string   `json:"package"`
	Test                string   `json:"test"`
	New                 bool     `json:"new"`
	MeanSeconds         float64  `json:"mean_seconds"`
	BaselineMeanSeconds *float64 `json:"baseline_mean_seconds,omitempty"`
	DeltaSeconds        *float64 `json:"delta_seconds,omitempty"`
	DeltaPercent        *float64 `json:"delta_percent,omitempty"`
}

type resources struct {
	UserCPUSeconds   *float64 `json:"user_cpu_seconds,omitempty"`
	SystemCPUSeconds *float64 `json:"system_cpu_seconds,omitempty"`
	CPUScope         string   `json:"cpu_scope,omitempty"`
	MaxRSSBytes      *uint64  `json:"max_rss_bytes,omitempty"`
	MaxRSSScope      string   `json:"max_rss_scope,omitempty"`
}

type report struct {
	SchemaVersion   int        `json:"schema_version"`
	Mode            string     `json:"mode"`
	Status          string     `json:"status"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	ExitCode        *int       `json:"exit_code,omitempty"`
	Canceled        bool       `json:"canceled"`
	Complete        bool       `json:"complete"`
	CollectionError bool       `json:"collection_error"`
	WallSeconds     *float64   `json:"wall_seconds,omitempty"`
	Resources       *resources `json:"resources,omitempty"`
	Timing          struct {
		EventSpanSeconds                   *float64 `json:"event_span_seconds,omitempty"`
		UncachedPackageElapsedSeconds      *float64 `json:"uncached_package_elapsed_seconds,omitempty"`
		UncachedTopLevelTestElapsedSeconds *float64 `json:"uncached_top_level_test_elapsed_seconds,omitempty"`
		PackageIntervalUnionSeconds        *float64 `json:"package_interval_union_seconds,omitempty"`
		OutsidePackageEstimateSeconds      *float64 `json:"outside_package_intervals_estimate_seconds,omitempty"`
	} `json:"timing"`
	InvalidRecords int             `json:"invalid_records"`
	UnknownEvents  int             `json:"unknown_events"`
	BuildFailures  int             `json:"build_failures"`
	Packages       []packageMetric `json:"packages"`
	Cases          []caseMetric    `json:"cases"`
	Comparisons    []comparison    `json:"comparisons,omitempty"`
	Warnings       []string        `json:"warnings"`
	Limitations    []string        `json:"limitations"`
}

type caseKey struct{ pkg, test string }
type interval struct{ start, end time.Time }
type packageState struct {
	packageMetric
	start    time.Time
	started  bool
	terminal bool
}

// Only the current line and metrics are retained, never the complete test log.
type analyzer struct {
	human                    io.Writer
	line                     []byte
	oversized                bool
	invalid, unknown, builds int
	packages                 map[string]*packageState
	cases                    map[caseKey]*caseMetric
	active                   map[caseKey]bool
	intervals                []interval
	first, last              time.Time
	commandStart, commandEnd time.Time
	writeErr                 error
}

func newAnalyzer(human io.Writer) *analyzer {
	return &analyzer{human: human, packages: map[string]*packageState{}, cases: map[caseKey]*caseMetric{}, active: map[caseKey]bool{}}
}

func (a *analyzer) Write(p []byte) (int, error) {
	length := len(p)
	for len(p) != 0 {
		i := bytes.IndexByte(p, '\n')
		n := len(p)
		if i >= 0 {
			n = i + 1
		}
		part := p[:n]
		p = p[n:]
		if !a.oversized && len(a.line)+len(part) > maxEventBytes {
			a.invalid++
			a.oversized = true
			a.emit(a.line)
			a.line = a.line[:0]
		}
		if a.oversized {
			a.emit(part)
		} else {
			a.line = append(a.line, part...)
		}
		if i >= 0 {
			if !a.oversized {
				a.record(a.line)
				a.line = a.line[:0]
			}
			a.oversized = false
		}
	}
	return length, a.writeErr
}

func (a *analyzer) emit(p []byte) {
	if a.writeErr == nil {
		var n int
		n, a.writeErr = a.human.Write(p)
		if a.writeErr == nil && n != len(p) {
			a.writeErr = io.ErrShortWrite
		}
	}
}

func (a *analyzer) finish() {
	if len(a.line) > 0 {
		// A final valid event need not have a trailing newline.
		a.record(a.line)
		a.line = nil
	}
}

func (a *analyzer) record(line []byte) {
	var e event
	if err := json.Unmarshal(line, &e); err != nil || e.Action == "" || (e.Elapsed != nil && !validElapsed(*e.Elapsed)) {
		a.invalid++
		a.emit(line)
		return
	}
	if e.Output != "" {
		a.emit([]byte(e.Output))
	}
	if !e.Time.IsZero() {
		if a.first.IsZero() || e.Time.Before(a.first) {
			a.first = e.Time
		}
		if e.Time.After(a.last) {
			a.last = e.Time
		}
	}
	if e.Action == "build-output" || e.Action == "build-fail" {
		if e.Action == "build-fail" {
			a.builds++
		}
		return
	}
	switch e.Action {
	case "start", "run", "pause", "cont", "pass", "fail", "skip", "output", "bench":
	default:
		a.unknown++
		return
	}
	if e.Package == "" {
		a.invalid++
		return
	}
	pkg := a.packages[e.Package]
	if pkg == nil {
		pkg = &packageState{packageMetric: packageMetric{Package: e.Package, Status: "incomplete"}}
		a.packages[e.Package] = pkg
	}
	if e.Test == "" {
		switch e.Action {
		case "start":
			if pkg.started && !pkg.terminal {
				a.invalid++
			}
			pkg.start = e.Time
			pkg.started = true
			pkg.terminal = false
		case "output":
			out := strings.TrimSpace(e.Output)
			if (strings.HasPrefix(out, "ok\t") || strings.HasPrefix(out, "ok ")) && strings.Contains(out, "(cached)") {
				pkg.Cached = true
			}
		case "pass", "fail", "skip":
			pkg.Status = worse(pkg.Status, e.Action)
			pkg.terminal = true
			addSeconds(&pkg.ElapsedSeconds, e.Elapsed)
			if !pkg.Cached && !pkg.start.IsZero() && !e.Time.Before(pkg.start) {
				a.intervals = append(a.intervals, interval{pkg.start, e.Time})
			}
		}
		return
	}
	key := caseKey{e.Package, e.Test}
	switch e.Action {
	case "run":
		a.active[key] = true
	case "pass", "fail", "skip":
		delete(a.active, key)
		c := a.cases[key]
		if c == nil {
			c = &caseMetric{Package: e.Package, Test: e.Test, Nested: strings.Contains(e.Test, "/")}
			a.cases[key] = c
			pkg.Cases++
		}
		c.Status = worse(c.Status, e.Action)
		c.Runs++
		if e.Elapsed != nil {
			c.TimedRuns++
		}
		addSeconds(&c.ElapsedSeconds, e.Elapsed)
	case "bench":
		delete(a.active, key)
	}
}

func worse(a, b string) string {
	weight := map[string]int{"": 0, "incomplete": 0, "skip": 1, "pass": 2, "fail": 3}
	if weight[b] > weight[a] {
		return b
	}
	return a
}

func addSeconds(to **float64, value *float64) {
	if value == nil {
		return
	}
	if *to == nil {
		*to = seconds(0)
	}
	**to += *value
}

func (a *analyzer) fill(r *report, baseline *report) {
	r.InvalidRecords, r.UnknownEvents, r.BuildFailures = a.invalid, a.unknown, a.builds
	r.Packages = make([]packageMetric, 0, len(a.packages))
	r.Cases = make([]caseMetric, 0, len(a.cases))
	r.Complete = !r.CollectionError && a.invalid == 0 && a.unknown == 0 && len(a.packages) > 0 && len(a.active) == 0 && a.writeErr == nil
	failed := a.builds > 0 || (r.ExitCode != nil && *r.ExitCode != 0)
	for key := range a.active {
		c := a.cases[key]
		if c == nil {
			c = &caseMetric{Package: key.pkg, Test: key.test, Nested: strings.Contains(key.test, "/")}
			a.cases[key] = c
			a.packages[key.pkg].Cases++
		}
		failed = failed || c.Status == "fail"
		c.Status = "incomplete"
	}
	for _, p := range a.packages {
		r.Packages = append(r.Packages, p.packageMetric)
		r.Complete = r.Complete && p.started && p.terminal
		failed = failed || p.Status == "fail"
		if !p.Cached && p.ElapsedSeconds != nil {
			addSeconds(&r.Timing.UncachedPackageElapsedSeconds, p.ElapsedSeconds)
		}
	}
	for key, c := range a.cases {
		c.Cached = a.packages[key.pkg].Cached
		r.Cases = append(r.Cases, *c)
		failed = failed || c.Status == "fail"
		if !c.Cached && !c.Nested && c.ElapsedSeconds != nil {
			addSeconds(&r.Timing.UncachedTopLevelTestElapsedSeconds, c.ElapsedSeconds)
		}
	}
	if !a.first.IsZero() {
		r.Timing.EventSpanSeconds = seconds(a.last.Sub(a.first).Seconds())
	}
	if len(a.intervals) > 0 {
		// In run mode, event clocks are bounded by the actual command window.
		if !a.commandStart.IsZero() {
			for i := range a.intervals {
				a.intervals[i].start = later(a.intervals[i].start, a.commandStart)
				a.intervals[i].end = earlier(a.intervals[i].end, a.commandEnd)
			}
		}
		union := unionSeconds(a.intervals)
		r.Timing.PackageIntervalUnionSeconds = &union
		if r.WallSeconds != nil {
			r.Timing.OutsidePackageEstimateSeconds = seconds(math.Max(0, *r.WallSeconds-union))
		}
	}
	sort.Slice(r.Cases, func(i, j int) bool {
		a, b := r.Cases[i], r.Cases[j]
		if a.Cached != b.Cached {
			return !a.Cached
		}
		if value(a.ElapsedSeconds) != value(b.ElapsedSeconds) {
			return value(a.ElapsedSeconds) > value(b.ElapsedSeconds)
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Test < b.Test
	})
	sort.Slice(r.Packages, func(i, j int) bool {
		a, b := r.Packages[i], r.Packages[j]
		if a.Cached != b.Cached {
			return !a.Cached
		}
		if value(a.ElapsedSeconds) != value(b.ElapsedSeconds) {
			return value(a.ElapsedSeconds) > value(b.ElapsedSeconds)
		}
		return a.Package < b.Package
	})
	if baseline != nil {
		r.Comparisons = compare(r.Cases, baseline.Cases)
		if !baseline.Complete || baseline.Status != "pass" {
			r.Warnings = append(r.Warnings, "Baseline was not a complete passing run; comparisons may be partial.")
		}
	}
	r.Status = "pass"
	if !r.Complete || r.Canceled {
		r.Status = "incomplete"
	}
	if failed {
		r.Status = "fail"
	}
	if !r.Complete {
		r.Warnings = append(r.Warnings, "Incomplete or unrecognized Go JSON stream; missing results are not passes.")
	}
	r.Warnings = append(r.Warnings, "Informational timing only: no calibrated performance thresholds or gates. Review slow/new cases and baseline deltas.")
	r.Limitations = []string{
		"Command wall is observed by the wrapper and includes output draining, but excludes building/starting testreport itself and final report serialization. Resource accounting belongs to the invoked command, not the wrapper.",
		"Go JSON Elapsed is reported test/package duration, not compiler CPU time. Cached durations are replayed, not measured in this run.",
		"Outside-package time is an estimate from command wall time minus the union of uncached package start-to-terminal event intervals. It may include build, startup, scheduling, gaps and output handling; it misses builds overlapping tests and is not an exact compile time.",
		"Package and top-level test elapsed sums may overlap due to parallelism. Nested subtests are listed but excluded from the top-level sum; parent durations already include them. Paused test time and package event intervals differ from reported Elapsed.",
		"CPU accounting is OS ProcessState accounting, not sampled process-tree utilization. RSS, when available, is an OS single-process peak, not aggregate concurrent RAM. Missing measurements are omitted.",
		"Baseline comparisons use mean elapsed per completed occurrence, omit cached/skipped/incompletely timed cases, and do not control for runner, Go version, flags, test selection or load. New means absent from comparable baseline data, not necessarily a newly added test.",
	}
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func unionSeconds(intervals []interval) float64 {
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].start.Before(intervals[j].start) })
	var total float64
	var current interval
	for _, next := range intervals {
		if next.end.Before(next.start) {
			continue
		}
		if current.start.IsZero() {
			current = next
		} else if next.start.After(current.end) {
			total += current.end.Sub(current.start).Seconds()
			current = next
		} else {
			current.end = later(current.end, next.end)
		}
	}
	if !current.start.IsZero() {
		total += current.end.Sub(current.start).Seconds()
	}
	return total
}

func comparable(c caseMetric) bool {
	return !c.Cached && (c.Status == "pass" || c.Status == "fail") && c.ElapsedSeconds != nil && c.Runs > 0 && c.TimedRuns == c.Runs
}

func compare(current, previous []caseMetric) []comparison {
	old := map[caseKey]caseMetric{}
	for _, c := range previous {
		if comparable(c) {
			old[caseKey{c.Package, c.Test}] = c
		}
	}
	result := []comparison{}
	for _, c := range current {
		if !comparable(c) {
			continue
		}
		n := comparison{Package: c.Package, Test: c.Test, MeanSeconds: *c.ElapsedSeconds / float64(c.Runs)}
		if p, exists := old[caseKey{c.Package, c.Test}]; exists {
			mean := *p.ElapsedSeconds / float64(p.Runs)
			n.BaselineMeanSeconds = &mean
			n.DeltaSeconds = seconds(n.MeanSeconds - mean)
			if mean > 0 {
				pct := *n.DeltaSeconds / mean * 100
				if !math.IsInf(pct, 0) {
					n.DeltaPercent = &pct
				}
			}
		} else {
			n.New = true
		}
		result = append(result, n)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.New != b.New {
			return !a.New
		}
		if value(a.DeltaSeconds) != value(b.DeltaSeconds) {
			return value(a.DeltaSeconds) > value(b.DeltaSeconds)
		}
		if a.MeanSeconds != b.MeanSeconds {
			return a.MeanSeconds > b.MeanSeconds
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Test < b.Test
	})
	return result
}

func value(p *float64) float64 {
	if p == nil {
		return -1
	}
	return *p
}

func validElapsed(value float64) bool {
	// test2json durations originate in time.Duration. This is a representability
	// bound, not a performance threshold; it also prevents aggregate overflow.
	return value >= 0 && value <= time.Duration(1<<63-1).Seconds()
}

func readBaseline(path string) (*report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil {
		return nil, err
	} else if info.Size() > 32*1024*1024 {
		return nil, fmt.Errorf("baseline exceeds 32 MiB")
	}
	var r report
	dec := json.NewDecoder(io.LimitReader(f, 32*1024*1024))
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	if r.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported schema version %d", r.SchemaVersion)
	}
	for _, c := range r.Cases {
		if c.ElapsedSeconds != nil && !validElapsed(*c.ElapsedSeconds) {
			return nil, fmt.Errorf("invalid baseline duration")
		}
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("unexpected trailing baseline data")
	}
	return &r, nil
}

func writeReport(dir string, r *report, top int) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	jsonErr := os.WriteFile(filepath.Join(dir, "report.json"), append(data, '\n'), 0o600)
	mdErr := os.WriteFile(filepath.Join(dir, "report.md"), []byte(markdown(r, top)), 0o600)
	return errors.Join(jsonErr, mdErr)
}

func cell(s string) string {
	s = html.EscapeString(s)
	s = strings.ReplaceAll(s, "|", "&#124;")
	s = strings.ReplaceAll(s, "`", "&#96;")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "[", "&#91;")
	s = strings.ReplaceAll(s, "]", "&#93;")
	s = strings.ReplaceAll(s, "*", "&#42;")
	s = strings.ReplaceAll(s, "_", "&#95;")
	s = strings.ReplaceAll(s, "\\", "&#92;")
	return s
}

func duration(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.3f s", *v)
}

func markdown(r *report, top int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Go test report\n\n**Result: %s** · complete: %t", r.Status, r.Complete)
	if r.ExitCode != nil {
		fmt.Fprintf(&b, " · command exit: %d", *r.ExitCode)
	}
	fmt.Fprintln(&b)
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\n> **Warning:** %s\n", cell(w))
	}
	fmt.Fprintf(&b, "\n| Measurement | Value |\n| --- | ---: |\n| Command wall | %s |\n| Go JSON event span | %s |\n| Uncached package elapsed sum (overlapping) | %s |\n| Uncached top-level test elapsed sum (overlapping) | %s |\n| Uncached package event interval union | %s |\n| Outside-package estimate; **not compile time** | %s |\n", duration(r.WallSeconds), duration(r.Timing.EventSpanSeconds), duration(r.Timing.UncachedPackageElapsedSeconds), duration(r.Timing.UncachedTopLevelTestElapsedSeconds), duration(r.Timing.PackageIntervalUnionSeconds), duration(r.Timing.OutsidePackageEstimateSeconds))
	if res := r.Resources; res != nil {
		fmt.Fprintf(&b, "| User CPU | %s |\n| System CPU | %s |\n", duration(res.UserCPUSeconds), duration(res.SystemCPUSeconds))
		if res.MaxRSSBytes != nil {
			fmt.Fprintf(&b, "| OS peak RSS (not aggregate RAM) | %d bytes |\n", *res.MaxRSSBytes)
		}
		fmt.Fprintf(&b, "\nCPU scope: %s\n", cell(res.CPUScope))
		if res.MaxRSSScope != "" {
			fmt.Fprintf(&b, "\nRSS scope: %s\n", cell(res.MaxRSSScope))
		}
	}
	fmt.Fprintf(&b, "\n## Slow cases (top %d)\n\nNested cases are included in their parents; do not sum this table. Cached timings are historical.\n\n| Package | Test | Reported elapsed sum | Timed / runs | Result | Cached |\n| --- | --- | ---: | ---: | --- | --- |\n", top)
	for i, c := range r.Cases {
		if i >= top {
			break
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d / %d | %s | %t |\n", cell(c.Package), cell(c.Test), duration(c.ElapsedSeconds), c.TimedRuns, c.Runs, cell(c.Status), c.Cached)
	}
	fmt.Fprintf(&b, "\n## Packages (top %d)\n\n| Package | Elapsed sum | Result | Cached |\n| --- | ---: | --- | --- |\n", top)
	for i, p := range r.Packages {
		if i >= top {
			break
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %t |\n", cell(p.Package), duration(p.ElapsedSeconds), cell(p.Status), p.Cached)
	}
	if r.Comparisons != nil {
		fmt.Fprintf(&b, "\n## Baseline increases (top %d; informational)\n\nMean elapsed per completed occurrence; no threshold or environment normalization.\n\n| Package | Test | Current mean | Baseline mean | Increase |\n| --- | --- | ---: | ---: | ---: |\n", top)
		count := 0
		for _, c := range r.Comparisons {
			if count >= top {
				break
			}
			if c.New || c.DeltaSeconds == nil || *c.DeltaSeconds <= 0 {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", cell(c.Package), cell(c.Test), duration(&c.MeanSeconds), duration(c.BaselineMeanSeconds), duration(c.DeltaSeconds))
			count++
		}
		fmt.Fprintf(&b, "\n## Newly observed cases (top %d)\n\nAbsent from comparable baseline data; not necessarily newly added tests.\n\n| Package | Test | Mean |\n| --- | --- | ---: |\n", top)
		count = 0
		for _, c := range r.Comparisons {
			if count >= top {
				break
			}
			if !c.New {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", cell(c.Package), cell(c.Test), duration(&c.MeanSeconds))
			count++
		}
	}
	fmt.Fprintf(&b, "\nStream diagnostics: %d invalid records, %d unknown actions, %d build failures.\n\n## Measurement limits\n", r.InvalidRecords, r.UnknownEvents, r.BuildFailures)
	for _, limit := range r.Limitations {
		fmt.Fprintf(&b, "\n- %s\n", cell(limit))
	}
	return b.String()
}

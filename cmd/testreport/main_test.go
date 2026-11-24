package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func loadReport(t *testing.T, dir string) report {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "report.md")); err != nil {
		t.Fatal(err)
	}
	return r
}

func helperArgs(mode string, extra ...string) []string {
	return append([]string{os.Args[0], "-test.run=^TestReportChild$", "--", "testreport-child", mode}, extra...)
}

func TestReportChild(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "testreport-child" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	args := os.Args[index+1:]
	switch args[0] {
	case "success", "exit7", "invalid":
		fmt.Fprintln(os.Stderr, "helper diagnostic")
		if args[0] == "invalid" {
			fmt.Println("not JSON")
		} else {
			fmt.Println("{\"Action\":\"start\",\"Package\":\"fixture\"}")
			fmt.Println("{\"Action\":\"output\",\"Package\":\"fixture\",\"Output\":\"human output ü\\n\"}")
			fmt.Println("{\"Action\":\"pass\",\"Package\":\"fixture\",\"Elapsed\":0.1}")
		}
		if args[0] == "exit7" {
			os.Exit(7)
		}
		os.Exit(0)
	case "large":
		fmt.Println("{\"Action\":\"start\",\"Package\":\"fixture\"}")
		for i := 0; i < 6000; i++ {
			fmt.Printf("{\"Action\":\"output\",\"Package\":\"fixture\",\"Output\":%q}\n", strings.Repeat("log", 128)+"\n")
		}
		fmt.Println("{\"Action\":\"pass\",\"Package\":\"fixture\"}")
		os.Exit(0)
	case "tree":
		child := exec.Command(os.Args[0], helperArgs("leaf", args[1], args[2])[1:]...)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			panic(err)
		}
		fmt.Println("{\"Action\":\"start\",\"Package\":\"fixture\"}")
		time.Sleep(time.Minute)
		os.Exit(0)
	case "leaf":
		if err := os.WriteFile(args[1], []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
			panic(err)
		}
		time.Sleep(time.Second)
		_ = os.WriteFile(args[2], []byte("survived"), 0o600)
		os.Exit(0)
	}
	os.Exit(9)
}

func TestRunExitAndArtifacts(t *testing.T) {
	t.Setenv("TESTREPORT_SECRET_SENTINEL", "NEVER_INCLUDE_ENV_IN_REPORT")
	for _, tc := range []struct {
		mode   string
		code   int
		status string
	}{
		{"success", 0, "pass"}, {"exit7", 7, "fail"}, {"invalid", 1, "incomplete"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "artifact directory with spaces")
			var human, stderr bytes.Buffer
			args := append([]string{"run", "--output", dir, "--"}, helperArgs(tc.mode)...)
			if code := cli(context.Background(), args, &human, &stderr); code != tc.code {
				t.Fatalf("exit %d, wanted %d; %s", code, tc.code, stderr.String())
			}
			r := loadReport(t, dir)
			if r.Status != tc.status || r.WallSeconds == nil || r.Resources == nil || r.Resources.UserCPUSeconds == nil {
				t.Fatalf("bad report: %+v", r)
			}
			expectedChildCode := tc.code
			if tc.mode == "invalid" {
				expectedChildCode = 0
			}
			if r.ExitCode == nil || *r.ExitCode != expectedChildCode {
				t.Fatalf("child exit overwritten: %+v", r.ExitCode)
			}
			if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
				if r.Resources.MaxRSSBytes == nil || *r.Resources.MaxRSSBytes == 0 {
					t.Fatal("missing supported RSS")
				}
			} else if runtime.GOOS == "windows" && r.Resources.MaxRSSBytes != nil {
				t.Fatal("invented Windows RSS")
			}
			raw, err := os.ReadFile(filepath.Join(dir, "raw.jsonl"))
			if err != nil || len(raw) == 0 {
				t.Fatalf("missing raw output: %v", err)
			}
			log, err := os.ReadFile(filepath.Join(dir, "stderr.log"))
			if err != nil || string(log) != "helper diagnostic\n" || stderr.String() != string(log) {
				t.Fatalf("stderr not preserved: %q %v", log, err)
			}
			if tc.mode != "invalid" && !strings.Contains(human.String(), "human output ü") {
				t.Fatalf("JSON not streamed for humans: %q", human.String())
			}
			data, _ := os.ReadFile(filepath.Join(dir, "report.json"))
			if bytes.Contains(data, []byte("NEVER_INCLUDE_ENV_IN_REPORT")) || bytes.Contains(data, []byte(os.Args[0])) {
				t.Fatal("environment/command leaked into report")
			}
		})
	}
}

func TestCancellationCleansDescendants(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("tree cancellation not supported on this OS")
	}
	dir := t.TempDir()
	ready, survived := filepath.Join(dir, "ready"), filepath.Join(dir, "survived")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan int, 1)
	var human, stderr bytes.Buffer
	args := append([]string{"run", "--output", filepath.Join(dir, "report"), "--"}, helperArgs("tree", ready, survived)...)
	go func() { result <- cli(ctx, args, &human, &stderr) }()
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		select {
		case code := <-result:
			t.Fatalf("child exited before ready: %d: %s", code, stderr.String())
		case <-deadline:
			t.Fatal("child did not become ready")
		case <-tick.C:
		}
	}
	cancel()
	select {
	case code := <-result:
		if code != 130 {
			t.Fatalf("cancel exit %d: %s", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not release child output pipes")
	}
	r := loadReport(t, filepath.Join(dir, "report"))
	if !r.Cancelled || r.Status == "pass" || r.Complete {
		t.Fatalf("cancel was green: %+v", r)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := os.Stat(survived); !os.IsNotExist(err) {
		t.Fatal("descendant survived cancellation")
	}
}

func TestRealGoTestSuccessFailureAndCache(t *testing.T) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool unavailable")
	}
	// The temporary module imports stdlib only; never fetch toolchains/modules.
	for key, value := range map[string]string{"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "", "GOWORK": "off", "GOENV": "off", "GOMAXPROCS": "2"} {
		t.Setenv(key, value)
	}
	dir := filepath.Join(t.TempDir(), "fixture with spaces")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module testreportfixture\n\ngo 1.27.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := "package fixture\nimport \"testing\"\nfunc TestSuccess(t *testing.T) { t.Log(\"fixture human output\") }\nfunc TestFailure(t *testing.T) { t.Fatal(\"intentional failure\") }\n"
	if err := os.WriteFile(filepath.Join(dir, "fixture_test.go"), []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, testName := range []string{"TestSuccess", "TestSuccess", "TestFailure"} {
		var human, stderr bytes.Buffer
		out := filepath.Join(dir, fmt.Sprintf("report-%d", i))
		args := []string{"run", "--output", out, "--", goPath, "-C", dir, "test", "-p", "1", "-json", "-run", "^" + testName + "$", "."}
		code := cli(context.Background(), args, &human, &stderr)
		r := loadReport(t, out)
		if i < 2 {
			if code != 0 || r.Status != "pass" || !r.Complete {
				t.Fatalf("success: exit %d, %+v; %s", code, r, stderr.String())
			}
			if !strings.Contains(human.String(), "fixture human output") {
				t.Fatalf("no human output: %s", human.String())
			}
		} else if code != 1 || r.Status != "fail" || !r.Complete {
			t.Fatalf("failure: exit %d, %+v; %s", code, r, stderr.String())
		}
		if i == 1 && (!r.Packages[0].Cached || !r.Cases[0].Cached) {
			t.Fatalf("cache replay not recognized: %+v; %s", r, human.String())
		}
	}
	// Verify current Go build diagnostics, not only testing.T failures.
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte("package fixture\nthis is not valid Go\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var human, stderr bytes.Buffer
	out := filepath.Join(dir, "build-failure")
	code := cli(context.Background(), []string{"run", "--output", out, "--", goPath, "-C", dir, "test", "-p", "1", "-json", "."}, &human, &stderr)
	r := loadReport(t, out)
	if code != 1 || r.Status != "fail" || r.BuildFailures == 0 || !strings.Contains(human.String()+stderr.String(), "broken.go") {
		t.Fatalf("build failure lost: %d %+v; %s; %s", code, r, human.String(), stderr.String())
	}

	// go run maps child exits to 1; the built wrapper must preserve them exactly.
	binary := filepath.Join(dir, "testreport.exe")
	build := exec.Command(goPath, "build", "-p", "1", "-o", binary, ".")
	if log, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build wrapper: %v: %s", err, log)
	}
	args := append([]string{"run", "--output", filepath.Join(dir, "binary-exit"), "--"}, helperArgs("exit7")...)
	child := exec.Command(binary, args...)
	if log, err := child.CombinedOutput(); err == nil {
		t.Fatalf("binary ignored child exit: %s", log)
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 7 {
		t.Fatalf("binary exit was not 7: %v: %s", err, log)
	}
}

func TestAnalyzeOptionsAndInputPreservation(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "raw.jsonl")
	data := "{\"Action\":\"start\",\"Package\":\"p\"}\r\n{\"Action\":\"pass\",\"Package\":\"p\",\"Elapsed\":0}"
	if err := os.WriteFile(input, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := cli(context.Background(), []string{"analyze", "--input", input, "--output", dir}, &out, &out); code != 2 {
		t.Fatalf("input overwrite accepted: %d", code)
	}
	if after, _ := os.ReadFile(input); string(after) != data {
		t.Fatal("input was truncated")
	}
	reportDir := filepath.Join(dir, "analyzed")
	if code := cli(context.Background(), []string{"analyze", "--input", input, "--output", reportDir}, &out, &out); code != 0 {
		t.Fatalf("analyze exit %d: %s", code, out.String())
	}
	r := loadReport(t, reportDir)
	if r.WallSeconds != nil || r.Resources != nil || r.ExitCode != nil || r.Timing.OutsidePackageEstimateSeconds != nil {
		t.Fatal("analyze fabricated process measurements")
	}
	for _, args := range [][]string{nil, {"run"}, {"run", "--output", dir}, {"analyze", "--input", input, "--output", dir, "extra"}, {"run", "--output", dir, "--top", "0", "--", "go"}, {"analyze", "--input", input, "--output", dir, "--baseline", "missing"}} {
		if code := cli(context.Background(), args, &out, &out); code != 2 {
			t.Fatalf("invalid args %q accepted: %d", args, code)
		}
	}
	if code := cli(context.Background(), []string{"run", "--help"}, &out, &out); code != 0 {
		t.Fatalf("help exit: %d", code)
	}
}

func TestFailedStartStillWritesReports(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if code := cli(context.Background(), []string{"run", "--output", dir, "--", filepath.Join(dir, "not-a-command")}, &out, &out); code == 0 {
		t.Fatal("failed start was green")
	}
	r := loadReport(t, dir)
	if r.Status != "incomplete" || r.Resources != nil || r.ExitCode != nil || !r.CollectionError {
		t.Fatalf("invented process data: %+v", r)
	}
}

func TestRunDrainsPipesAfterOutputFailure(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	args := append([]string{"run", "--output", dir, "--"}, helperArgs("large")...)
	code := cli(ctx, args, brokenWriter{}, &stderr)
	if ctx.Err() != nil {
		t.Fatal("writer failure pipe-blocked the child")
	}
	if code != 1 {
		t.Fatalf("writer failure exit %d: %s", code, stderr.String())
	}
	r := loadReport(t, dir)
	if !r.CollectionError || r.Status == "pass" || r.ExitCode == nil || *r.ExitCode != 0 {
		t.Fatalf("lost output error/child exit: %+v", r)
	}
	if info, err := os.Stat(filepath.Join(dir, "raw.jsonl")); err != nil || info.Size() < 2*1024*1024 {
		t.Fatalf("raw stream not fully drained: %v", err)
	}
}

func TestAnalyzeCancellationInterruptsInput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- analyzeInput(ctx, reader, newAnalyzer(&bytes.Buffer{})) }()
	cancel()
	select {
	case err := <-result:
		if err != context.Canceled {
			t.Fatalf("analyze cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("analyze did not interrupt its pipe read")
	}
}

func TestBaselineValidation(t *testing.T) {
	for _, data := range []string{"{}", "not json", "{\"schema_version\":99}", "{\"schema_version\":1}{}", "{\"schema_version\":1,\"cases\":[{\"elapsed_seconds\":-1}]}"} {
		path := filepath.Join(t.TempDir(), "baseline.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBaseline(path); err == nil {
			t.Fatalf("invalid baseline accepted: %s", data)
		}
	}
}

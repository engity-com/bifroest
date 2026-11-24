// Command testreport records a go test -json command without changing its arguments.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func cli(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "run" && args[0] != "analyze") {
		fmt.Fprintln(stderr, "Usage: testreport run --output DIR [--top N] [--baseline report.json] -- go test ... -json ...\n       testreport analyze --input raw.jsonl --output DIR [--top N] [--baseline report.json]")
		return 2
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "artifact directory: raw.jsonl, stderr.log (run only), report.json, report.md")
	input := flags.String("input", "", "Go JSON stream to analyze (analyze only; - reads stdin)")
	baselinePath := flags.String("baseline", "", "previous report.json; comparisons are informational, never performance gates")
	top := flags.Int("top", 15, "number of slow cases, packages and comparisons in Markdown (1-100)")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *output == "" || *top < 1 || *top > 100 || (args[0] == "run" && (*input != "" || flags.NArg() == 0)) || (args[0] == "analyze" && (*input == "" || flags.NArg() != 0)) {
		fmt.Fprintln(stderr, "testreport: invalid options; use run/analyze --help")
		return 2
	}
	var baseline *report
	if *baselinePath != "" {
		var err error
		baseline, err = readBaseline(*baselinePath)
		if err != nil {
			fmt.Fprintln(stderr, "testreport: cannot read baseline:", err)
			return 2
		}
	}
	// Open the input before creating artifacts, and never truncate it in place.
	var source io.ReadCloser
	if args[0] == "analyze" {
		if *input == "-" {
			source = os.Stdin
		} else {
			var err error
			source, err = os.Open(*input)
			if err != nil {
				fmt.Fprintln(stderr, "testreport: cannot open input:", err)
				return 2
			}
			defer source.Close()
			if sameFile(*input, filepath.Join(*output, "raw.jsonl")) {
				fmt.Fprintln(stderr, "testreport: input and output raw.jsonl must be different files")
				return 2
			}
		}
	}
	if err := os.MkdirAll(*output, 0o755); err != nil {
		fmt.Fprintln(stderr, "testreport: cannot create output:", err)
		return 2
	}
	raw, err := os.OpenFile(filepath.Join(*output, "raw.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "testreport: cannot create raw stream:", err)
		return 2
	}
	a := newAnalyzer(stdout)
	r := report{SchemaVersion: 1, Mode: args[0], Status: "incomplete"}
	code := 0
	var runErr error
	if args[0] == "run" {
		code, runErr = run(ctx, flags.Args(), *output, raw, a, stderr, &r)
	} else {
		runErr = analyzeInput(ctx, source, io.MultiWriter(raw, a))
		r.Canceled = ctx.Err() != nil
		if r.Canceled {
			code = 130
		}
	}
	a.finish()
	runErr = errors.Join(runErr, a.writeErr)
	if err := raw.Close(); err != nil {
		runErr = errors.Join(runErr, err)
	}
	if runErr != nil {
		// Command arguments, environment and child output do not belong in the summary.
		r.CollectionError = true
		r.Warnings = append(r.Warnings, "Command or artifact I/O failed; inspect stderr.log and the runner diagnostics.")
		fmt.Fprintln(stderr, "testreport:", runErr)
		if code == 0 {
			code = 1
		}
	}
	a.fill(&r, baseline)
	if code == 0 && r.Status != "pass" {
		code = 1
	}
	if err := writeReport(*output, &r, *top); err != nil {
		fmt.Fprintln(stderr, "testreport: cannot write summary:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func sameFile(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA == nil && errB == nil && aa == bb {
		return true
	}
	as, errA := os.Stat(a)
	bs, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(as, bs)
}

func analyzeInput(ctx context.Context, source io.ReadCloser, target io.Writer) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = source.Close() // Also interrupt a blocked --input - pipe read.
		case <-done:
		}
	}()
	_, err := io.Copy(target, source)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func run(ctx context.Context, args []string, output string, raw io.Writer, a *analyzer, stderr io.Writer, r *report) (int, error) {
	log, err := os.OpenFile(filepath.Join(output, "stderr.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 1, err
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	// Keep draining OS pipes even if a console or artifact sink fails. Returning
	// a writer error to os/exec can otherwise leave a verbose child pipe-blocked.
	childOut := newDrainingWriter(raw, a)
	childErr := newDrainingWriter(stderr, log)
	cmd.Stdout = childOut
	cmd.Stderr = childErr
	cmd.Stdin = os.Stdin
	afterStart, cleanup, err := configureCommand(cmd)
	if err != nil {
		return 1, err
	}
	defer cleanup()
	start := time.Now()
	a.commandStart = start
	r.StartedAt = &start
	err = cmd.Start()
	if err == nil {
		if attachErr := afterStart(); attachErr != nil {
			_ = cmd.Cancel()
			_ = cmd.Wait()
			err = attachErr
		} else {
			err = cmd.Wait()
		}
	}
	end := time.Now()
	a.commandEnd = end
	r.WallSeconds = seconds(end.Sub(start).Seconds())
	r.Resources = measureResources(cmd.ProcessState)
	r.Canceled = ctx.Err() != nil
	code := 0
	if err != nil {
		code = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() > 0 {
			code = exitErr.ExitCode()
			// A nonzero child exit is expected test information, not an I/O error.
			err = nil
		} else if cmd.ProcessState != nil {
			code = signalExitCode(cmd.ProcessState)
		}
	}
	if cmd.ProcessState != nil {
		r.ExitCode = new(int)
		*r.ExitCode = code
	}
	if r.Canceled {
		code = 130
	}
	return code, errors.Join(err, childOut.err(), childErr.err(), log.Close())
}

func seconds(value float64) *float64 { return &value }

type drainingWriter struct {
	writers []io.Writer
	errors  []error
}

func newDrainingWriter(writers ...io.Writer) *drainingWriter {
	return &drainingWriter{writers: writers, errors: make([]error, len(writers))}
}

func (w *drainingWriter) Write(p []byte) (int, error) {
	for i, sink := range w.writers {
		if w.errors[i] != nil {
			continue
		}
		n, err := sink.Write(p)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
		w.errors[i] = err
	}
	return len(p), nil
}

func (w *drainingWriter) err() error { return errors.Join(w.errors...) }

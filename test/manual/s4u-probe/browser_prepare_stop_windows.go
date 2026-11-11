//go:build windows

package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
)

type browserPreparationStopper interface {
	Query() (svc.Status, error)
	Control(svc.Cmd) (svc.Status, error)
}

func stopPreparedBrowserService(service browserPreparationStopper, deadline time.Time) error {
	// Publishing the result precedes reporting Running/AcceptStop to SCM.
	// Wait for that actual readiness, rather than sending a premature control
	// and retrying its failure. Readiness and shutdown share the original limit.
	stopSent := false
	for time.Now().Before(deadline) {
		status, err := service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			if !stopSent || status.Win32ExitCode != 0 {
				return fmt.Errorf("system preparation stopped unexpectedly: requested=%t exit=%d", stopSent, status.Win32ExitCode)
			}
			return nil
		}
		if !stopSent && status.State == svc.Running && status.Accepts&svc.AcceptStop != 0 {
			if _, err := service.Control(svc.Stop); err != nil {
				return err
			}
			stopSent = true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("system fixture preparation did not stop")
}

//go:build windows

package main

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/svc"
)

type preparationStopTestService struct {
	statuses          []svc.Status
	last              svc.Status
	queries, stops    int
	queryErr, stopErr error
}

func (s *preparationStopTestService) Query() (svc.Status, error) {
	s.queries++
	if s.queryErr != nil {
		return svc.Status{}, s.queryErr
	}
	if len(s.statuses) == 0 {
		return svc.Status{}, errors.New("unexpected extra service query")
	}
	s.last, s.statuses = s.statuses[0], s.statuses[1:]
	return s.last, nil
}

func (s *preparationStopTestService) Control(command svc.Cmd) (svc.Status, error) {
	s.stops++
	if command != svc.Stop || s.last.State != svc.Running || s.last.Accepts&svc.AcceptStop == 0 {
		return svc.Status{}, errors.New("premature or unexpected control request")
	}
	return svc.Status{State: svc.StopPending}, s.stopErr
}

func TestBrowserPreparationWaitsForScmStopReadinessAndStopsExactlyOnce(t *testing.T) {
	service := &preparationStopTestService{statuses: []svc.Status{
		{State: svc.StartPending},
		{State: svc.Running},
		{State: svc.Running, Accepts: svc.AcceptStop},
		{State: svc.StopPending},
		{State: svc.Stopped},
	}}
	require.NoError(t, stopPreparedBrowserService(service, time.Now().Add(time.Second)))
	require.Equal(t, 1, service.stops)
	require.Equal(t, 5, service.queries)
}

func TestBrowserPreparationDoesNotRetryErrorsOrAcceptUnexpectedStop(t *testing.T) {
	failure := errors.New("SCM failure")
	for _, service := range []*preparationStopTestService{
		{queryErr: failure},
		{statuses: []svc.Status{{State: svc.Running, Accepts: svc.AcceptStop}}, stopErr: failure},
	} {
		require.ErrorIs(t, stopPreparedBrowserService(service, time.Now().Add(time.Second)), failure)
		require.Equal(t, 1, service.queries)
		require.LessOrEqual(t, service.stops, 1)
	}
	for _, exit := range []uint32{0, 1} {
		service := &preparationStopTestService{statuses: []svc.Status{{State: svc.Stopped, Win32ExitCode: exit}}}
		require.Error(t, stopPreparedBrowserService(service, time.Now().Add(time.Second)))
		require.Zero(t, service.stops)
	}
	failed := &preparationStopTestService{statuses: []svc.Status{
		{State: svc.Running, Accepts: svc.AcceptStop},
		{State: svc.Stopped, Win32ExitCode: 1},
	}}
	require.Error(t, stopPreparedBrowserService(failed, time.Now().Add(time.Second)))
	require.Equal(t, 1, failed.stops)
	service := &preparationStopTestService{}
	require.Error(t, stopPreparedBrowserService(service, time.Now().Add(-time.Second)))
	require.Zero(t, service.queries)
	require.Zero(t, service.stops)
}

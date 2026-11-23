package main

import (
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/engity-com/bifroest/pkg/errors"
	bftest "github.com/engity-com/bifroest/pkg/test"
	"github.com/stretchr/testify/require"
)

func TestPolicyExitCodeDoesNotChangeOtherCommands(t *testing.T) {
	for _, code := range []int{1, 2} {
		err := fmt.Errorf("wrapped: %w", &bftest.CommandError{Code: code, Cause: errors.Config.Newf("test did not pass")})
		require.Equal(t, code, exitCode(err))
	}
	require.Equal(t, 1, exitCode(errors.Config.Newf("ordinary CLI failure")))
	for _, args := range [][]string{{"test"}, {"--log.level", "info", "test"}, {"--log.level=info", "test"}} {
		require.True(t, policyTestRequested(args))
	}
	for _, args := range [][]string{{"version"}, {"--log.level", "test", "version"}, {"@host", "test"}, {}} {
		require.False(t, policyTestRequested(args))
	}
}

func TestOnlyFullyReportedPolicyErrorsSuppressTheFinalLog(t *testing.T) {
	reported := &bftest.CommandError{Code: 1, Cause: errors.Config.Newf("assertions failed"), Reported: true}
	unreported := &bftest.CommandError{Code: 2, Cause: errors.System.Newf("report write failed")}
	for _, test := range []struct {
		err      error
		reported bool
	}{
		{nil, false},
		{reported, true},
		{fmt.Errorf("wrapped: %w", reported), true},
		{stderrors.Join(reported), true},
		{unreported, false},
		{errors.Config.Newf("ordinary command error"), false},
		{stderrors.Join(reported, errors.System.Newf("cleanup failed")), false},
		{stderrors.Join(reported, unreported), false},
	} {
		require.Equal(t, test.reported, errorWasReported(test.err))
	}
}

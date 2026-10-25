package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	configuration "github.com/engity-com/bifroest/pkg/configuration/names"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/google/uuid"
)

const MaximumEventNameBytes = 256
const MaximumEventTokenBytes = 256

func ValidateEvent(event Event) error            { return validateAuditEvent(event) }
func ValidateEventForWrite(event Event) error    { return validateAuditEventForWrite(event) }
func IsErrorCategory(value ErrorCategory) bool   { return isErrorCategory(value) }
func ValidateRecordingDigest(value string) error { return validateAuditRecordingDigest(value) }
func ValidateToken(name, value string) error     { return validateAuditToken(name, value) }

func validateAuditEvent(event Event) error {
	if event.Name == "" {
		return errors.System.Newf("audit event name is empty")
	}
	if strings.TrimSpace(event.Name) != event.Name {
		return errors.System.Newf("audit event name contains leading or trailing whitespace")
	}
	if len(event.Name) > MaximumEventNameBytes {
		return errors.System.Newf("audit event name exceeds %d bytes", MaximumEventNameBytes)
	}
	if event.Domain != "" && event.Domain != EventDomainAuthentication && event.Domain != EventDomainConnection && event.Domain != EventDomainHousekeeping && event.Domain != EventDomainPortForwarding && event.Domain != EventDomainSession {
		return errors.System.Newf("unknown audit event domain %q", event.Domain)
	}
	if event.Outcome != "" && event.Outcome != EventOutcomeSuccess && event.Outcome != EventOutcomeDenied && event.Outcome != EventOutcomeFailure && event.Outcome != EventOutcomeCanceled {
		return errors.System.Newf("unknown audit event outcome %q", event.Outcome)
	}
	if event.AuthenticationMethod != "" && event.AuthenticationMethod != AuthenticationMethodPublicKey && event.AuthenticationMethod != AuthenticationMethodPassword && event.AuthenticationMethod != AuthenticationMethodKeyboardInteractive && event.AuthenticationMethod != AuthenticationMethodBrowserRememberMe {
		return errors.System.Newf("unknown audit authentication method %q", event.AuthenticationMethod)
	}
	if event.AuthenticationPhase != "" && event.AuthenticationPhase != AuthenticationPhaseCandidate && event.AuthenticationPhase != AuthenticationPhaseVerified {
		return errors.System.Newf("unknown audit authentication phase %q", event.AuthenticationPhase)
	}
	if event.SessionTask != "" && event.SessionTask != SessionTaskShell && event.SessionTask != SessionTaskExec && event.SessionTask != SessionTaskSftp && event.SessionTask != SessionTaskSubsystem {
		return errors.System.Newf("unknown audit session task %q", event.SessionTask)
	}
	if event.SessionSubsystem != "" {
		if event.SessionTask != SessionTaskSftp && event.SessionTask != SessionTaskSubsystem {
			return errors.System.Newf("audit session subsystem requires a subsystem task")
		}
		if len(event.SessionSubsystem) > MaxSessionSubsystemBytes {
			return errors.System.Newf("audit session subsystem exceeds %d bytes", MaxSessionSubsystemBytes)
		}
		if !utf8.ValidString(event.SessionSubsystem) {
			return errors.System.Newf("audit session subsystem is not valid UTF-8")
		}
		if strings.IndexByte(event.SessionSubsystem, 0) >= 0 {
			return errors.System.Newf("audit session subsystem contains a NUL byte")
		}
	}
	if event.ErrorCategory != "" && !isErrorCategory(event.ErrorCategory) {
		return errors.System.Newf("unknown audit error category %q", event.ErrorCategory)
	}
	if event.Target != "" {
		if err := event.Target.Validate(); err != nil {
			return errors.System.Newf("illegal audit event target: %w", err)
		}
	}
	if err := validateAuditFlow(event.Flow); err != nil {
		return err
	}
	for name, value := range map[string]string{"authorization kind": event.AuthorizationKind, "reason": event.Reason} {
		if err := validateAuditToken(name, value); err != nil {
			return err
		}
	}
	for name, value := range map[string]string{"connection ID": event.ConnectionId, "session ID": event.SessionId, "operation ID": event.OperationId} {
		if err := validateAuditUuid(name, value); err != nil {
			return err
		}
	}
	if err := validateAuditRecordingUuid(event.RecordingId); err != nil {
		return err
	}
	if err := validateAuditRecordingDigest(event.RecordingDigest); err != nil {
		return err
	}
	if event.ExitCode != nil && *event.ExitCode < 0 {
		return errors.System.Newf("audit event exit code is negative")
	}
	for name, value := range map[string]*int64{"bytes read": event.BytesRead, "bytes written": event.BytesWritten, "duration millis": event.DurationMillis} {
		if value != nil && *value < 0 {
			return errors.System.Newf("audit event %s is negative", name)
		}
	}
	if event.Count != nil && *event.Count == 0 {
		return errors.System.Newf("audit event count is zero")
	}
	return nil
}

func validateAuditEventForWrite(event Event) error {
	if err := validateAuditEvent(event); err != nil {
		return err
	}
	if err := validateSessionRecordingAuditEvent(event); err != nil {
		return err
	}
	return validateSessionRecordingDeliveryAuditEvent(event)
}

func validateSessionRecordingAuditEvent(event Event) error {
	switch event.Name {
	case EventNameSessionRecordingStarted, EventNameSessionRecordingCompleted, EventNameSessionRecordingIncomplete, EventNameSessionRecordingFailed:
	default:
		return nil
	}
	if event.Domain != EventDomainSession || event.Flow == "" || event.ConnectionId == "" || event.SessionId == "" || event.OperationId == "" || event.RecordingId == "" {
		return errors.System.Newf("session recording audit event lacks required correlation fields")
	}
	if event.SessionTask != SessionTaskShell && event.SessionTask != SessionTaskExec {
		return errors.System.Newf("session recording audit event has illegal task %q", event.SessionTask)
	}
	if event.AuthenticationMethod != "" || event.AuthenticationPhase != "" || event.AuthorizationKind != "" || event.Target != "" || event.BytesRead != nil || event.BytesWritten != nil || event.Count != nil || event.AgentForwarding != nil || event.ForcedCommand != nil {
		return errors.System.Newf("session recording audit event has unrelated fields")
	}
	switch event.Name {
	case EventNameSessionRecordingStarted:
		if event.Outcome != "" || event.Reason != "" || event.ErrorCategory != "" || event.RecordingDigest != "" || event.Pty == nil || event.DurationMillis != nil || event.ExitCode != nil {
			return errors.System.Newf("session recording started audit event has illegal lifecycle fields")
		}
	case EventNameSessionRecordingCompleted:
		if event.Outcome != EventOutcomeSuccess || event.Reason != "" || event.ErrorCategory != "" || event.RecordingDigest == "" || event.Pty != nil || event.DurationMillis == nil || event.ExitCode == nil {
			return errors.System.Newf("session recording completed audit event lacks required completion fields")
		}
	case EventNameSessionRecordingIncomplete:
		if event.RecordingDigest == "" || event.Pty != nil || event.DurationMillis == nil {
			return errors.System.Newf("session recording incomplete audit event lacks required completion fields")
		}
		valid := event.Outcome == EventOutcomeCanceled && event.ErrorCategory == "" && (event.Reason == EventReasonContextCanceled || event.Reason == EventReasonDeadlineExceeded) || event.Outcome == EventOutcomeFailure && event.ErrorCategory == "" && event.Reason == EventReasonInvalidExitCode || event.Outcome == EventOutcomeFailure && event.ErrorCategory == "" && event.Reason == EventReasonStartupRecovery && event.ExitCode == nil || event.Outcome == EventOutcomeFailure && event.Reason == EventReasonSessionError && event.ErrorCategory != ""
		if !valid {
			return errors.System.Newf("session recording incomplete audit event has illegal outcome and reason")
		}
		if event.Reason == EventReasonInvalidExitCode && event.ExitCode != nil {
			return errors.System.Newf("session recording invalid-exit audit event has an exit code")
		}
	case EventNameSessionRecordingFailed:
		validReason := event.Reason == EventReasonRecordingCreate || event.Reason == EventReasonRecordingCapture || event.Reason == EventReasonRecordingSeal || event.Reason == EventReasonAuditWrite
		startupFieldsInvalid := (event.Reason == EventReasonRecordingCreate || event.Reason == EventReasonAuditWrite) && event.ExitCode != nil
		createFieldsInvalid := event.Reason == EventReasonRecordingCreate && (event.RecordingDigest != "" || event.DurationMillis != nil)
		if event.Outcome != EventOutcomeFailure || !validReason || event.ErrorCategory == "" || event.Pty != nil || event.RecordingDigest != "" && event.DurationMillis == nil || startupFieldsInvalid || createFieldsInvalid {
			return errors.System.Newf("session recording failed audit event lacks required failure fields")
		}
	}
	return nil
}

func validateSessionRecordingDeliveryAuditEvent(event Event) error {
	switch event.Name {
	case EventNameSessionRecordingDeliveryFailed, EventNameSessionRecordingDeliverySucceeded:
	default:
		return nil
	}
	if event.Domain != EventDomainSession || event.OperationId == "" || event.RecordingId == "" || event.Target == "" {
		return errors.System.Newf("session recording delivery audit event lacks required correlation fields")
	}
	if event.Flow != "" || event.ConnectionId != "" || event.SessionId != "" || event.RecordingDigest != "" || event.AuthenticationMethod != "" || event.AuthenticationPhase != "" || event.AuthorizationKind != "" || event.SessionTask != "" || event.Reason != "" || event.ExitCode != nil || event.BytesRead != nil || event.BytesWritten != nil || event.DurationMillis != nil || event.Count != nil || event.Pty != nil || event.AgentForwarding != nil || event.ForcedCommand != nil {
		return errors.System.Newf("session recording delivery audit event has unrelated fields")
	}
	if event.Name == EventNameSessionRecordingDeliveryFailed {
		if event.Outcome != EventOutcomeFailure || event.ErrorCategory == "" {
			return errors.System.Newf("session recording delivery failed audit event lacks required failure fields")
		}
	} else if event.Outcome != EventOutcomeSuccess || event.ErrorCategory != "" {
		return errors.System.Newf("session recording delivery succeeded audit event has illegal outcome fields")
	}
	return nil
}
func isErrorCategory(v ErrorCategory) bool {
	return v == ErrorCategoryUnknown || v == ErrorCategorySystem || v == ErrorCategoryConfig || v == ErrorCategoryNetwork || v == ErrorCategoryUser || v == ErrorCategoryPermission || v == ErrorCategoryExpired
}
func validateAuditFlow(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > configuration.MaxFlowNameBytes {
		return errors.System.Newf("audit event flow exceeds %d bytes", configuration.MaxFlowNameBytes)
	}
	if value == "." || value == ".." {
		return errors.System.Newf("illegal audit event flow %q", value)
	}
	for _, c := range value {
		if !isAuditTokenCharacter(c) {
			return errors.System.Newf("illegal audit event flow %q", value)
		}
	}
	return nil
}
func validateAuditToken(name, value string) error {
	if value == "" {
		return nil
	}
	if len(value) > MaximumEventTokenBytes {
		return errors.System.Newf("audit event %s exceeds %d bytes", name, MaximumEventTokenBytes)
	}
	for _, c := range value {
		if !isAuditTokenCharacter(c) {
			return errors.System.Newf("illegal audit event %s %q", name, value)
		}
	}
	return nil
}
func isAuditTokenCharacter(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.'
}
func validateAuditUuid(name, value string) error {
	if value == "" {
		return nil
	}
	v, err := uuid.Parse(value)
	if err != nil || v == uuid.Nil || v.String() != value {
		return errors.System.Newf("illegal audit event %s %q", name, value)
	}
	return nil
}
func validateAuditRecordingUuid(value string) error {
	if value == "" {
		return nil
	}
	v, err := uuid.Parse(value)
	if err != nil || v == uuid.Nil || v.Version() != 4 || v.Variant() != uuid.RFC4122 || v.String() != value {
		return errors.System.Newf("illegal audit event recording ID %q", value)
	}
	return nil
}
func validateAuditRecordingDigest(value string) error {
	if value == "" {
		return nil
	}
	if len(value) != sha256.Size*2 {
		return errors.System.Newf("illegal audit event recording digest %q", value)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return errors.System.Newf("illegal audit event recording digest %q", value)
	}
	return nil
}

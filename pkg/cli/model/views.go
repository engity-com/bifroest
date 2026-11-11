package model

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/management/protocol"
)

type FlowSummary struct {
	Name          configuration.FlowName     `json:"name" yaml:"name"`
	Auditlog      configuration.AuditlogName `json:"auditlog" yaml:"auditlog"`
	Authorization string                     `json:"authorization" yaml:"authorization"`
	Environment   string                     `json:"environment" yaml:"environment"`
}

type SessionView = protocol.SessionView

type SessionActionResult = protocol.SessionActionResult

type AuditlogSummary struct {
	Name             configuration.AuditlogName `json:"name" yaml:"name"`
	Enabled          bool                       `json:"enabled" yaml:"enabled"`
	RecordingEnabled bool                       `json:"recordingEnabled" yaml:"recordingEnabled"`
	Encrypted        bool                       `json:"encrypted" yaml:"encrypted"`
}

type RecordingView = protocol.RecordingView

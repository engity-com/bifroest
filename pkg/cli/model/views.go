package model

import (
	"time"

	"github.com/engity-com/bifroest/pkg/configuration"
)

type FlowSummary struct {
	Name          configuration.FlowName     `json:"name" yaml:"name"`
	Auditlog      configuration.AuditlogName `json:"auditlog" yaml:"auditlog"`
	Authorization string                     `json:"authorization" yaml:"authorization"`
	Environment   string                     `json:"environment" yaml:"environment"`
}

type SessionView struct {
	ID           string     `json:"id" yaml:"id"`
	Flow         string     `json:"flow" yaml:"flow"`
	State        string     `json:"state" yaml:"state"`
	User         string     `json:"user" yaml:"user"`
	Remote       string     `json:"remote" yaml:"remote"`
	CreatedAt    time.Time  `json:"createdAt" yaml:"createdAt"`
	LastAccessed *time.Time `json:"lastAccessed,omitempty" yaml:"lastAccessed,omitempty"`
	ValidUntil   *time.Time `json:"validUntil,omitempty" yaml:"validUntil,omitempty"`
}

type SessionActionResult struct {
	ID     string `json:"id" yaml:"id"`
	Flow   string `json:"flow" yaml:"flow"`
	Action string `json:"action" yaml:"action"`
}

type AuditlogSummary struct {
	Name             configuration.AuditlogName `json:"name" yaml:"name"`
	Enabled          bool                       `json:"enabled" yaml:"enabled"`
	RecordingEnabled bool                       `json:"recordingEnabled" yaml:"recordingEnabled"`
	Encrypted        bool                       `json:"encrypted" yaml:"encrypted"`
}

type RecordingView struct {
	Auditlog             string    `json:"auditlog" yaml:"auditlog"`
	ID                   string    `json:"id" yaml:"id"`
	ProducerID           string    `json:"producerId" yaml:"producerId"`
	Format               string    `json:"format" yaml:"format"`
	Status               string    `json:"status" yaml:"status"`
	StartedAt            time.Time `json:"startedAt" yaml:"startedAt"`
	EndedAt              time.Time `json:"endedAt" yaml:"endedAt"`
	ContainerBytes       int64     `json:"containerBytes" yaml:"containerBytes"`
	ChunkCount           uint64    `json:"chunkCount" yaml:"chunkCount"`
	Encrypted            bool      `json:"encrypted" yaml:"encrypted"`
	RecipientFingerprint string    `json:"recipientFingerprint,omitempty" yaml:"recipientFingerprint,omitempty"`
	VerificationScope    string    `json:"verificationScope" yaml:"verificationScope"`
}

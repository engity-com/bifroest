package management

import (
	"fmt"

	"github.com/alecthomas/kingpin/v2"
)

// AuditArtifactCommand registers the same subject/verb hierarchy for local
// offline processing and direct SSH management. Only source-specific flags and
// actions differ between the two execution environments.
func AuditArtifactCommand(parent *kingpin.CmdClause, name string) *kingpin.CmdClause {
	var description string
	switch name {
	case "producer-id":
		description = "Print the signing producer ID of an audit log."
	case "verify":
		description = "Verify a signed audit journal without modifying it."
	case "export":
		description = "Export verified audit events as JSON Lines."
	case "decrypt":
		description = "Alias for audit export (verified JSON Lines)."
	case "merge":
		description = "Merge verified audit journals chronologically as JSON Lines."
	default:
		panic(fmt.Errorf("unsupported audit artifact command %q", name))
	}
	return parent.Command(name, description)
}

// RecordingArtifactCommand keeps named local/offline and direct SSH commands
// in the same command tree even though direct SSH cannot decrypt recordings.
func RecordingArtifactCommand(parent *kingpin.CmdClause, name string) *kingpin.CmdClause {
	var description string
	switch name {
	case "verify":
		description = "Verify a signed session Recording."
	case "export":
		description = "Verify and export a session Recording as asciicast v3."
	case "play":
		description = "Verify and play a session Recording in the terminal."
	default:
		panic(fmt.Errorf("unsupported Recording artifact command %q", name))
	}
	return parent.Command(name, description)
}

func AuditSensitiveFlag(cmd *kingpin.CmdClause, target *bool) {
	cmd.Flag("with-sensitive", "Include private audit event fields; encrypted journals need a local decryption identity.").BoolVar(target)
}

func RecordingSensitiveFlag(cmd *kingpin.CmdClause, target *bool) {
	cmd.Flag("with-sensitive", "Explicitly authorize access to sensitive Recording content.").BoolVar(target)
}

func RequireFullVerificationFlag(cmd *kingpin.CmdClause, target *bool) {
	cmd.Flag("require-full", "Fail if encrypted content cannot be fully verified without a local private key.").BoolVar(target)
}

func VerificationFormatFlag(cmd *kingpin.CmdClause, target *string) {
	cmd.Flag("format", "Display verification as text, JSON, or YAML.").Default("table").EnumVar(target, "table", "json", "yaml")
}

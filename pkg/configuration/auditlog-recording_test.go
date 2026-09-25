package configuration

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/template"
)

func expectedDefaultAuditlogRecording() AuditlogRecording {
	return AuditlogRecording{
		Enabled:           DefaultAuditlogRecordingEnabled,
		Directory:         DefaultAuditlogRecordingDirectory,
		Compression:       DefaultAuditlogRecordingCompression,
		ChunkSizeBytes:    DefaultAuditlogRecordingChunkSizeBytes,
		FlushInterval:     DefaultAuditlogRecordingFlushInterval,
		FlushSizeBytes:    DefaultAuditlogRecordingFlushSizeBytes,
		MaximumSpoolBytes: DefaultAuditlogRecordingMaximumSpoolBytes,
		RetainFor:         DefaultAuditlogRecordingRetainFor,
		Notice:            DefaultAuditlogRecordingNotice,
	}
}

func TestAuditlogRecordingUnmarshalYAML(t *testing.T) {
	runUnmarshalYamlTests(t,
		unmarshalYamlTestCase[AuditlogRecording]{
			name:     "defaults",
			yaml:     `{}`,
			expected: expectedDefaultAuditlogRecording(),
		},
		unmarshalYamlTestCase[AuditlogRecording]{
			name: "custom",
			yaml: `
enabled: true
directory: "  custom-recordings  "
compression:
  level: default
chunkSizeBytes: 1048577
flushInterval: 1500ms
flushSizeBytes: 2097152
maximumSpoolBytes: 4294967296
retainFor: 0s
notice: "  Recording enabled  "
targets:
- name: "  archive  "
  type: s3
  bucket: recording-archive`,
			expected: AuditlogRecording{
				Enabled:           true,
				Directory:         "custom-recordings",
				Compression:       DefaultAuditlogRecordingCompression,
				ChunkSizeBytes:    MaximumAuditlogRecordingChunkSizeBytes,
				FlushInterval:     common.DurationOf(1500 * time.Millisecond),
				FlushSizeBytes:    2 << 20,
				MaximumSpoolBytes: 4 << 30,
				RetainFor:         common.DurationOf(0),
				Notice:            template.MustNewString("  Recording enabled  "),
				Targets: AuditlogRecordingTargets{
					Mode: AuditlogRecordingTargetsModeCustom,
					Targets: AuditlogTargets{{Name: "archive", V: &AuditlogTargetS3{
						Bucket:                "recording-archive",
						Region:                DefaultAuditlogTargetS3Region,
						AccessKeyId:           DefaultAuditlogTargetS3AccessKeyId,
						SecretAccessKey:       DefaultAuditlogTargetS3SecretAccessKey,
						SessionToken:          DefaultAuditlogTargetS3SessionToken,
						PublishAttemptTimeout: DefaultAuditlogTargetPublishAttemptTimeout,
						sessionTokenDefault:   true,
					}}},
				},
			},
		},
		unmarshalYamlTestCase[AuditlogRecording]{
			name:          "empty-directory",
			yaml:          `directory: " "`,
			expectedError: `[directory] required but absent`,
		},
		unmarshalYamlTestCase[AuditlogRecording]{
			name:          "invalid-notice",
			yaml:          `notice: "{{"`,
			expectedError: `illegal string template`,
		},
		unmarshalYamlTestCase[AuditlogRecording]{
			name:          "negative-retention",
			yaml:          `retainFor: -1s`,
			expectedError: `[retainFor] must be greater than or equal to 0`,
		},
	)
}

func TestAuditlogRecordingCompression(t *testing.T) {
	for _, value := range []string{"fast", "DEFAULT", " default ", ""} {
		t.Run(fmt.Sprintf("reject-%q", value), func(t *testing.T) {
			var compression AuditlogRecordingCompression
			err := yaml.Unmarshal([]byte(fmt.Sprintf("level: %q", value)), &compression)
			require.ErrorContains(t, err, "illegal compression level")
		})
	}

	var defaults AuditlogRecordingCompression
	require.NoError(t, yaml.Unmarshal([]byte(`{}`), &defaults))
	require.True(t, defaults.IsEqualTo(DefaultAuditlogRecordingCompression))
	require.True(t, AuditlogRecordingCompressionLevelDefault.IsEqualTo("default"))
	require.Equal(t, AuditlogRecordingCompressionLevelDefault, AuditlogRecordingCompressionLevelDefault.Clone())

	var unknown AuditlogRecordingCompression
	require.ErrorContains(t, yaml.Unmarshal([]byte(`unknown: true`), &unknown), "field unknown not found")
}

func TestAuditlogRecordingLimits(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*AuditlogRecording)
		errorPart string
	}{
		{"zero chunk", func(value *AuditlogRecording) { value.ChunkSizeBytes = 0 }, "[chunkSizeBytes] must be between"},
		{"oversized chunk", func(value *AuditlogRecording) { value.ChunkSizeBytes = MaximumAuditlogRecordingChunkSizeBytes + 1 }, "[chunkSizeBytes] must be between"},
		{"zero flush interval", func(value *AuditlogRecording) { value.FlushInterval = common.DurationOf(0) }, "[flushInterval] must be positive"},
		{"negative flush interval", func(value *AuditlogRecording) { value.FlushInterval = common.DurationOf(-time.Second) }, "[flushInterval] must be positive"},
		{"zero flush size", func(value *AuditlogRecording) { value.FlushSizeBytes = 0 }, "[flushSizeBytes] must be positive"},
		{"zero spool", func(value *AuditlogRecording) { value.MaximumSpoolBytes = 0 }, "[maximumSpoolBytes] must be positive"},
		{"spool below chunk", func(value *AuditlogRecording) { value.MaximumSpoolBytes = value.ChunkSizeBytes - 1 }, "greater than or equal to chunkSizeBytes"},
		{"spool below flush", func(value *AuditlogRecording) { value.MaximumSpoolBytes = value.FlushSizeBytes - 1 }, "greater than or equal to flushSizeBytes"},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := expectedDefaultAuditlogRecording()
			test.configure(&value)
			require.ErrorContains(t, value.Validate(), test.errorPart)
		})
	}

	value := expectedDefaultAuditlogRecording()
	value.RetainFor = common.DurationOf(0)
	require.NoError(t, value.Validate())
	value.RetainFor = common.DurationOf(-time.Nanosecond)
	require.ErrorContains(t, value.Validate(), "[retainFor] must be greater than or equal to 0")
}

func TestAuditlogRecordingProgrammaticZeroValue(t *testing.T) {
	var recording AuditlogRecording
	require.True(t, recording.IsZero())
	require.NoError(t, recording.Validate())

	recording.Directory = "recordings"
	require.False(t, recording.IsZero())
	require.ErrorContains(t, recording.Validate(), "[compression] [level]")

	auditlog := Auditlog{
		Name:         "security",
		Enabled:      true,
		IdentityFile: "identity",
		Directory:    "journal",
	}
	require.NoError(t, auditlog.Validate())
	require.NoError(t, Auditlogs{auditlog}.Validate())
}

func TestAuditlogRecordingTargets(t *testing.T) {
	var absent AuditlogRecording
	require.NoError(t, yaml.Unmarshal([]byte(`{}`), &absent))
	for _, value := range []string{"null", "[]", "inherit"} {
		t.Run("inherit-"+value, func(t *testing.T) {
			var targets AuditlogRecordingTargets
			require.NoError(t, yaml.Unmarshal([]byte(value), &targets))
			require.True(t, targets.IsInherited())
			require.False(t, targets.IsDisabled())
			require.Nil(t, targets.Configured())
			require.True(t, targets.IsEqualTo(AuditlogRecordingTargets{}))
			var recording AuditlogRecording
			require.NoError(t, yaml.Unmarshal([]byte("targets: "+value), &recording))
			require.True(t, absent.Targets.IsEqualTo(recording.Targets))
			recordingYAML, err := yaml.Marshal(recording)
			require.NoError(t, err)
			require.Contains(t, string(recordingYAML), "targets: inherit")
			encoded, err := yaml.Marshal(targets)
			require.NoError(t, err)
			require.Equal(t, "inherit\n", string(encoded))
		})
	}

	for _, value := range []string{"false", `" false "`, "off", `" OFF "`, "no", `" No "`} {
		t.Run("disabled-"+value, func(t *testing.T) {
			var targets AuditlogRecordingTargets
			require.NoError(t, yaml.Unmarshal([]byte(value), &targets))
			require.True(t, targets.IsDisabled())
			require.False(t, targets.IsInherited())
			require.Nil(t, targets.Configured())
			encoded, err := yaml.Marshal(targets)
			require.NoError(t, err)
			require.Equal(t, "false\n", string(encoded))
		})
	}

	for _, value := range []string{"true", `"true"`, "on", "yes", "unknown", "INHERIT", `" inherit "`, `""`, "{}", "1", "1.5", "[false]", "[null]", "[name]", "[{name: archive, type: s3, bucket: recording-archive}, false]"} {
		t.Run("reject-"+value, func(t *testing.T) {
			var targets AuditlogRecordingTargets
			require.Error(t, yaml.Unmarshal([]byte(value), &targets))
		})
	}
}

func TestAuditlogRecordingTargetsDecodeConcreteTargets(t *testing.T) {
	var recording AuditlogRecording
	require.NoError(t, yaml.Unmarshal([]byte(`
targets:
- name: s3-archive
  type: s3
  bucket: recording-archive
- name: webdav-archive
  type: webdav
  endpoint: https://archive.example.invalid/recordings
- name: sftp-archive
  type: sftp
  address: archive.example.invalid:22
  user: archive
  directory: /recordings
  acceptAllHostKeys: true
  identityFiles: [archive-key]
`), &recording))

	targets := recording.Targets.Configured()
	require.Len(t, targets, 3)
	require.IsType(t, &AuditlogTargetS3{}, targets[0].V)
	require.IsType(t, &AuditlogTargetWebdav{}, targets[1].V)
	require.IsType(t, &AuditlogTargetSftp{}, targets[2].V)

	encoded, err := yaml.Marshal(recording)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "required:")
	var roundTripped AuditlogRecording
	require.NoError(t, yaml.Unmarshal(encoded, &roundTripped))
	require.True(t, recording.IsEqualTo(roundTripped))
}

func TestAuditlogRecordingTargetsPreserveRegisteredCodecs(t *testing.T) {
	var recording AuditlogRecording
	require.NoError(t, yaml.Unmarshal([]byte(`
targets:
- name: custom
  type: test-remote-alias
  endpoint: " custom.example.invalid "
  required: codec-specific
`), &recording))
	target := recording.Targets.Configured()[0]
	require.Equal(t, &testAuditlogTarget{Endpoint: "custom.example.invalid", Required: "codec-specific", defaultCalls: 1}, target.V)

	encoded, err := yaml.Marshal(recording.Targets)
	require.NoError(t, err)
	require.Contains(t, string(encoded), "type: test-remote")
	require.Contains(t, string(encoded), "required: codec-specific")
	require.NotContains(t, string(encoded), "test-remote-alias")
	var roundTripped AuditlogRecordingTargets
	require.NoError(t, yaml.Unmarshal(encoded, &roundTripped))
	require.True(t, recording.Targets.IsEqualTo(roundTripped))
}

func TestAuditlogRecordingTargetsRejectInvalidConcreteTargets(t *testing.T) {
	for _, test := range []struct {
		name     string
		yaml     string
		expected string
	}{
		{"unknown-field", "targets:\n- name: archive\n  type: s3\n  bucket: recording-archive\n  unknown: true", "field unknown not found"},
		{"duplicate-name", "targets:\n- name: archive\n  type: s3\n  bucket: recording-archive\n- name: ' archive '\n  type: s3\n  bucket: recording-copy", "duplicates"},
		{"missing-type", "targets:\n- name: archive", "[type] required but absent"},
		{"unknown-recording-field", "targets:\n- name: archive\n  type: s3\n  bucket: recording-archive\n  required: true", "field required not found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var recording AuditlogRecording
			require.ErrorContains(t, yaml.Unmarshal([]byte(test.yaml), &recording), test.expected)
		})
	}
}

func TestAuditlogRecordingPreservesExplicitZeroValuesAcrossYAMLRoundTrip(t *testing.T) {
	recording := expectedDefaultAuditlogRecording()
	recording.RetainFor = common.DurationOf(0)
	recording.Targets = AuditlogRecordingTargets{
		Mode: AuditlogRecordingTargetsModeCustom,
		Targets: AuditlogTargets{{Name: "archive", V: &AuditlogTargetS3{
			Bucket:                "recording-archive",
			Region:                DefaultAuditlogTargetS3Region,
			AccessKeyId:           DefaultAuditlogTargetS3AccessKeyId,
			SecretAccessKey:       DefaultAuditlogTargetS3SecretAccessKey,
			SessionToken:          DefaultAuditlogTargetS3SessionToken,
			PublishAttemptTimeout: DefaultAuditlogTargetPublishAttemptTimeout,
			sessionTokenDefault:   true,
		}}},
	}

	payload, err := yaml.Marshal(recording)
	require.NoError(t, err)
	require.Contains(t, string(payload), "retainFor: 0s")
	require.NotContains(t, string(payload), "required:")

	var decoded AuditlogRecording
	require.NoError(t, yaml.Unmarshal(payload, &decoded))
	require.True(t, recording.IsEqualTo(decoded))
}

func TestAuditlogRecordingParentValidation(t *testing.T) {
	var parentDisabled Auditlog
	require.ErrorContains(t, yaml.Unmarshal([]byte("recording:\n  enabled: true"), &parentDisabled), "[recording][enabled] requires [enabled] to be true")

	var inherited Auditlog
	require.NoError(t, yaml.Unmarshal([]byte(`
enabled: true
targets:
- name: archive
  type: s3
  bucket: recording-archive
recording:
  enabled: true`), &inherited))
	require.True(t, inherited.Recording.Targets.IsInherited())

	var separate Auditlog
	require.NoError(t, yaml.Unmarshal([]byte(`
enabled: true
recording:
  enabled: true
  targets:
  - name: separate
    type: s3
    bucket: separate-recordings
`), &separate))
	require.Equal(t, AuditlogTargetName("separate"), separate.Recording.Targets.Configured()[0].Name)
}

func TestAuditlogRecordingStrictUnknownFields(t *testing.T) {
	for _, field := range []string{"identityFile", "encryptionPublicKey", "encryptionPublicKeyFile", "signature", "innerSignature", "outerSignature", "failOpen", "maximumRecordingBytes", "maximumPlaintextBytes"} {
		t.Run(field, func(t *testing.T) {
			var auditlog Auditlog
			err := yaml.Unmarshal([]byte(fmt.Sprintf("recording:\n  %s: value", field)), &auditlog)
			require.ErrorContains(t, err, "field "+field+" not found")
		})
	}
}

func TestAuditlogRecordingEquality(t *testing.T) {
	left := expectedDefaultAuditlogRecording()
	right := left
	require.True(t, left.IsEqualTo(right))
	right.Notice = template.MustNewString("notice")
	require.False(t, left.IsEqualTo(right))
	require.False(t, left.IsEqualTo(nil))

	inherited := AuditlogRecordingTargets{}
	disabled := AuditlogRecordingTargets{Mode: AuditlogRecordingTargetsModeDisabled}
	custom := AuditlogRecordingTargets{Mode: AuditlogRecordingTargetsModeCustom, Targets: AuditlogTargets{{
		Name: "archive", V: &testAuditlogTarget{Endpoint: "archive.example.invalid"},
	}}}
	require.False(t, inherited.IsEqualTo(disabled))
	require.False(t, inherited.IsEqualTo(custom))
	require.False(t, disabled.IsEqualTo(custom))
	require.True(t, custom.IsEqualTo(custom))
}

func TestAuditlogRecordingStaticPathOverlaps(t *testing.T) {
	root := t.TempDir()
	newAuditlog := func(name string) Auditlog {
		recording := expectedDefaultAuditlogRecording()
		recording.Enabled = true
		recording.Directory = filepath.Join(root, name+"-recordings")
		return Auditlog{
			Name:         AuditlogName(name),
			Enabled:      true,
			IdentityFile: filepath.Join(root, name+"-identity"),
			Directory:    filepath.Join(root, name+"-journal"),
			Recording:    recording,
		}
	}

	t.Run("recording roots", func(t *testing.T) {
		first, second := newAuditlog("first"), newAuditlog("second")
		second.Recording.Directory = filepath.Join(first.Recording.Directory, "second")
		require.ErrorContains(t, Auditlogs{first, second}.Validate(), "[1][recording][directory] overlaps enabled auditlog [0][recording][directory]")
	})
	t.Run("every journal", func(t *testing.T) {
		first, second := newAuditlog("first"), newAuditlog("second")
		second.Directory = filepath.Join(first.Recording.Directory, "journal")
		require.ErrorContains(t, Auditlogs{first, second}.Validate(), "[0][recording][directory] overlaps enabled auditlog [1][directory]")
	})
	t.Run("every identity", func(t *testing.T) {
		first, second := newAuditlog("first"), newAuditlog("second")
		second.IdentityFile = filepath.Join(first.Recording.Directory, "identity")
		require.ErrorContains(t, Auditlogs{first, second}.Validate(), "[0][recording][directory] overlaps enabled auditlog [1][identityFile]")
	})
	t.Run("other auditlog encryption key", func(t *testing.T) {
		first, second := newAuditlog("first"), newAuditlog("second")
		second.EncryptionPublicKeyFile = crypto.PublicKeysFile(filepath.Join(first.Recording.Directory, "recipient.pub"))
		require.ErrorContains(t, Auditlogs{first, second}.Validate(), "[0][recording][directory] overlaps enabled auditlog [1][encryptionPublicKeyFile]")
	})
	t.Run("other auditlog SFTP known hosts", func(t *testing.T) {
		first, second := newAuditlog("first"), newAuditlog("second")
		sftp := validRecordingPathSftpTarget(t, root)
		sftp.AcceptAllHostKeys = false
		sftp.KnownHostsFile = crypto.KnownHostsFile(filepath.Join(first.Recording.Directory, "known_hosts"))
		second.Targets = AuditlogTargets{{Name: "archive", V: sftp}}
		require.ErrorContains(t, Auditlogs{first, second}.Validate(), "[0][recording][directory] overlaps enabled auditlog [1][targets][0][knownHostsFile]")
	})
	t.Run("other auditlog SFTP identity", func(t *testing.T) {
		first, second := newAuditlog("first"), newAuditlog("second")
		sftp := validRecordingPathSftpTarget(t, root)
		sftp.IdentityFiles = []string{filepath.Join(first.Recording.Directory, "identity")}
		second.Targets = AuditlogTargets{{Name: "archive", V: sftp}}
		require.ErrorContains(t, Auditlogs{first, second}.Validate(), "[0][recording][directory] overlaps enabled auditlog [1][targets][0][identityFiles][0]")
	})
	t.Run("custom Recording SFTP known hosts", func(t *testing.T) {
		first, second := newAuditlog("first"), newAuditlog("second")
		sftp := validRecordingPathSftpTarget(t, root)
		sftp.AcceptAllHostKeys = false
		sftp.KnownHostsFile = crypto.KnownHostsFile(filepath.Join(first.Recording.Directory, "known_hosts"))
		second.Recording.Targets = customRecordingPathTargets(sftp)
		require.ErrorContains(t, Auditlogs{first, second}.Validate(), "[0][recording][directory] overlaps enabled auditlog [1][recording][targets][0][knownHostsFile]")
	})
	t.Run("custom Recording SFTP identity", func(t *testing.T) {
		first, second := newAuditlog("first"), newAuditlog("second")
		sftp := validRecordingPathSftpTarget(t, root)
		sftp.IdentityFiles = []string{filepath.Join(first.Recording.Directory, "identity")}
		second.Recording.Targets = customRecordingPathTargets(sftp)
		require.ErrorContains(t, Auditlogs{first, second}.Validate(), "[0][recording][directory] overlaps enabled auditlog [1][recording][targets][0][identityFiles][0]")
	})
	t.Run("disabled recording", func(t *testing.T) {
		auditlog := newAuditlog("first")
		auditlog.Recording.Enabled = false
		auditlog.Recording.Directory = auditlog.Directory
		sftp := validRecordingPathSftpTarget(t, root)
		sftp.IdentityFiles = []string{filepath.Join(root, "first-journal", "identity")}
		auditlog.Recording.Targets = customRecordingPathTargets(sftp)
		require.NoError(t, Auditlogs{auditlog}.Validate())
	})
	t.Run("remote delivery disabled", func(t *testing.T) {
		auditlog := newAuditlog("first")
		auditlog.Recording.Targets = AuditlogRecordingTargets{Mode: AuditlogRecordingTargetsModeDisabled}
		require.NoError(t, Auditlogs{auditlog}.Validate())
	})
}

func TestConfigurationRejectsRecordingSessionStorageOverlap(t *testing.T) {
	root := t.TempDir()
	recording := expectedDefaultAuditlogRecording()
	recording.Enabled = true
	recording.Directory = filepath.Join(root, "recordings")
	conf := Configuration{
		Auditlogs: Auditlogs{{Name: "default", Enabled: true, Recording: recording}},
		Session:   Session{V: &SessionFs{Storage: filepath.Join(recording.Directory, "sessions")}},
	}
	require.ErrorContains(t, conf.validateRecordingSessionStoragePathOverlaps(), "[auditlog][0][recording][directory] overlaps [session][storage]")

	conf.Auditlogs[0].Recording.Enabled = false
	require.NoError(t, conf.validateRecordingSessionStoragePathOverlaps())
}

func TestConfigurationValidateIncludesRecordingSessionStorageOverlap(t *testing.T) {
	var conf Configuration
	require.NoError(t, yaml.Unmarshal([]byte(`
flows:
- name: foo
  authorization:
    type: oidcDeviceAuth
    issuer: https://example.com
    clientId: client
    clientSecret: secret
  environment:
    type: local
    name: user`), &conf))
	root := t.TempDir()
	conf.Auditlogs[0].Enabled = true
	conf.Auditlogs[0].IdentityFile = filepath.Join(root, "identity")
	conf.Auditlogs[0].Directory = filepath.Join(root, "journal")
	conf.Auditlogs[0].Recording.Enabled = true
	conf.Auditlogs[0].Recording.Directory = filepath.Join(root, "storage", "recordings")
	conf.Session.V.(*SessionFs).Storage = filepath.Join(root, "storage")

	require.ErrorContains(t, conf.Validate(), "[auditlog][0][recording][directory] overlaps [session][storage]")
}

func validRecordingPathSftpTarget(t *testing.T, root string) *AuditlogTargetSftp {
	t.Helper()
	result := &AuditlogTargetSftp{}
	require.NoError(t, result.SetDefaults())
	result.Address = "localhost:22"
	result.User = template.MustNewString("archive")
	result.Directory = "/archive"
	result.AcceptAllHostKeys = true
	result.IdentityFiles = []string{filepath.Join(root, "sftp-identity")}
	return result
}

func customRecordingPathTargets(sftp *AuditlogTargetSftp) AuditlogRecordingTargets {
	return AuditlogRecordingTargets{
		Mode:    AuditlogRecordingTargetsModeCustom,
		Targets: AuditlogTargets{{Name: "recording-archive", V: sftp}},
	}
}

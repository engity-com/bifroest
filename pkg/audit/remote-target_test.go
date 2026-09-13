package audit

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestSealedSegmentMetadataAndRemotePath(t *testing.T) {
	segment := validRemoteTargetTestSegment()
	require.NoError(t, segment.Validate())
	require.Equal(t, ProducerId{1}, segment.ProducerId())
	require.Equal(t, uint64(42), segment.Sequence())
	require.Equal(t, int64(len("sealed segment")), segment.Size())
	require.Equal(t, "segment-00000000000000000042-"+segment.Hash().String()+".journal", segment.FileName())
	require.Equal(t, segment.ProducerId().String()+"/"+segment.FileName(), segment.RemotePath())
	require.NotContains(t, segment.RemotePath(), `\`)
	first, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	second, err := io.ReadAll(segment.Content())
	require.NoError(t, err)
	require.Equal(t, first, second)
}

func TestSealedSegmentValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SealedSegment)
		err    string
	}{
		{"producer", func(value *SealedSegment) { value.producerId = ProducerId{} }, "producer ID"},
		{"sequence", func(value *SealedSegment) { value.sequence = 0 }, "sequence"},
		{"hash", func(value *SealedSegment) { value.hash = SegmentHash{} }, "hash"},
		{"zero-size", func(value *SealedSegment) { value.size = 0 }, "size"},
		{"negative-size", func(value *SealedSegment) { value.size = -1 }, "size"},
		{"short-size", func(value *SealedSegment) { value.size-- }, "exceeds declared size"},
		{"long-size", func(value *SealedSegment) { value.size++ }, "content size"},
		{"wrong-hash", func(value *SealedSegment) { value.hash[0]++ }, "does not match hash"},
		{"content", func(value *SealedSegment) { value.content = nil }, "content"},
		{"typed-nil-content", func(value *SealedSegment) { value.content = (*bytes.Reader)(nil) }, "content"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			segment := validRemoteTargetTestSegment()
			test.mutate(&segment)
			require.ErrorContains(t, segment.Validate(), test.err)
		})
	}
}

func TestSegmentHashText(t *testing.T) {
	expected := SegmentHash{1, 2, 3}
	var actual SegmentHash
	require.NoError(t, actual.UnmarshalText([]byte(expected.String())))
	require.Equal(t, expected, actual)
	require.Error(t, actual.UnmarshalText([]byte("short")))
	require.Error(t, actual.UnmarshalText([]byte(strings.Repeat("z", 64))))
}

func TestRemoteDeliveryTargetSettingsExcludeCredentialsAndTimeout(t *testing.T) {
	base := &configuration.AuditlogTargetS3{
		Bucket:              "audit-archive",
		Region:              template.MustNewString("eu-central-1"),
		Prefix:              "production",
		Endpoint:            "https://objects.example.invalid",
		DestinationIdentity: "tenant-a",
		PathStyle:           true,
		AccessKeyId:         template.MustNewString("old-access"),
		SecretAccessKey:     template.MustNewString("old-secret"),
	}
	timeout, fingerprint, err := remoteDeliveryTargetSettings(base)
	require.NoError(t, err)
	require.Equal(t, 2*time.Minute, timeout)

	rotated := *base
	rotated.SecretAccessKey = template.MustNewString("new-secret")
	rotated.SessionToken = template.MustNewString("new-session-token")
	rotated.PublishAttemptTimeout = template.DurationOf(15 * time.Second)
	rotatedTimeout, rotatedFingerprint, err := remoteDeliveryTargetSettings(&rotated)
	require.NoError(t, err)
	require.Equal(t, 15*time.Second, rotatedTimeout)
	require.Equal(t, fingerprint, rotatedFingerprint)
	rotated.AccessKeyId = template.MustNewString("new-access")
	_, stsFingerprint, err := remoteDeliveryTargetSettings(&rotated)
	require.NoError(t, err)
	require.Equal(t, fingerprint, stsFingerprint)
	tenant := rotated
	tenant.DestinationIdentity = "tenant-b"
	_, tenantFingerprint, err := remoteDeliveryTargetSettings(&tenant)
	require.NoError(t, err)
	require.NotEqual(t, fingerprint, tenantFingerprint)

	for _, mutate := range []func(*configuration.AuditlogTargetS3){
		func(value *configuration.AuditlogTargetS3) { value.Endpoint = "https://other.example.invalid" },
		func(value *configuration.AuditlogTargetS3) { value.Region = template.MustNewString("us-east-1") },
		func(value *configuration.AuditlogTargetS3) { value.Bucket = "other-archive" },
		func(value *configuration.AuditlogTargetS3) { value.Prefix = "other" },
		func(value *configuration.AuditlogTargetS3) { value.PathStyle = false },
	} {
		changed := *base
		mutate(&changed)
		_, changedFingerprint, err := remoteDeliveryTargetSettings(&changed)
		require.NoError(t, err)
		require.NotEqual(t, fingerprint, changedFingerprint)
	}

	webdav := &configuration.AuditlogTargetWebdav{
		Endpoint: "https://dav.example.invalid/audit/",
		Username: template.MustNewString("archive"),
		Password: template.MustNewString("old-secret"),
	}
	_, webdavFingerprint, err := remoteDeliveryTargetSettings(webdav)
	require.NoError(t, err)
	webdav.Password = template.MustNewString("new-secret")
	_, rotatedWebdavFingerprint, err := remoteDeliveryTargetSettings(webdav)
	require.NoError(t, err)
	require.Equal(t, webdavFingerprint, rotatedWebdavFingerprint)
	webdav.Username = template.MustNewString("other-account")
	_, otherWebdavFingerprint, err := remoteDeliveryTargetSettings(webdav)
	require.NoError(t, err)
	require.NotEqual(t, webdavFingerprint, otherWebdavFingerprint)

	sftp := &configuration.AuditlogTargetSftp{
		Address:        "sftp.example.invalid",
		User:           template.MustNewString("archive"),
		Directory:      "/audit",
		Password:       template.MustNewString("old-secret"),
		ConnectTimeout: configuration.DefaultAuditlogTargetSftpConnectTimeout,
	}
	_, sftpFingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	sftp.Password = template.MustNewString("new-secret")
	_, rotatedSftpFingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	require.Equal(t, sftpFingerprint, rotatedSftpFingerprint)
	sftp.User = template.MustNewString("other-account")
	_, otherSftpFingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	require.NotEqual(t, sftpFingerprint, otherSftpFingerprint)

	sftp.User = template.MustNewString("archive")
	sftp.Password = template.String{}
	sftp.IdentityFiles = []string{"first-key"}
	_, firstKeyFingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	sftp.IdentityFiles = []string{"second-key"}
	_, secondKeyFingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	require.Equal(t, firstKeyFingerprint, secondKeyFingerprint)
}

func TestRemoteDeliveryTargetSettingsUseEffectiveEndpointForms(t *testing.T) {
	webdav := &configuration.AuditlogTargetWebdav{Endpoint: "HTTPS://DAV.EXAMPLE.INVALID:0443/audit"}
	_, webdavFingerprint, err := remoteDeliveryTargetSettings(webdav)
	require.NoError(t, err)
	webdav.Endpoint = "https://dav.example.invalid/audit/"
	_, normalizedWebdavFingerprint, err := remoteDeliveryTargetSettings(webdav)
	require.NoError(t, err)
	require.Equal(t, webdavFingerprint, normalizedWebdavFingerprint)
	webdav.Endpoint = "https://dav.example.invalid/other/"
	_, otherWebdavFingerprint, err := remoteDeliveryTargetSettings(webdav)
	require.NoError(t, err)
	require.NotEqual(t, webdavFingerprint, otherWebdavFingerprint)

	s3 := &configuration.AuditlogTargetS3{
		Endpoint:            "HTTPS://OBJECTS.EXAMPLE.INVALID:0443",
		DestinationIdentity: "tenant-a",
		Region:              template.MustNewString("eu-central-1"),
		Bucket:              "audit-archive",
		AccessKeyId:         template.MustNewString("access"),
		SecretAccessKey:     template.MustNewString("secret"),
	}
	_, s3Fingerprint, err := remoteDeliveryTargetSettings(s3)
	require.NoError(t, err)
	s3.Endpoint = "https://objects.example.invalid"
	_, normalizedS3Fingerprint, err := remoteDeliveryTargetSettings(s3)
	require.NoError(t, err)
	require.Equal(t, s3Fingerprint, normalizedS3Fingerprint)

	sftp := &configuration.AuditlogTargetSftp{
		Address:        "sftp.example.invalid",
		User:           template.MustNewString("archive"),
		Password:       template.MustNewString("secret"),
		ConnectTimeout: configuration.DefaultAuditlogTargetSftpConnectTimeout,
	}
	_, sftpFingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	sftp.Address += ":22"
	_, normalizedSftpFingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	require.Equal(t, sftpFingerprint, normalizedSftpFingerprint)
	sftp.Address = "SFTP.EXAMPLE.INVALID:22"
	_, uppercaseSftpFingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	require.Equal(t, sftpFingerprint, uppercaseSftpFingerprint)

	sftp.Address = "[FE80::1%CaseSensitiveZone]:22"
	_, zonedIPv6Fingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	sftp.Address = "[fe80::1%CaseSensitiveZone]:22"
	_, normalizedZonedIPv6Fingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	require.Equal(t, zonedIPv6Fingerprint, normalizedZonedIPv6Fingerprint)
	sftp.Address = "[fe80::1%casesensitivezone]:22"
	_, otherZoneFingerprint, err := remoteDeliveryTargetSettings(sftp)
	require.NoError(t, err)
	require.NotEqual(t, zonedIPv6Fingerprint, otherZoneFingerprint)
}

func TestSealedSegmentValidationHonorsContextWhileHashing(t *testing.T) {
	content := []byte("sealed segment")
	segment := SealedSegment{
		producerId: ProducerId{1},
		sequence:   1,
		hash:       SegmentHash(hashJournalBytes(journalSegmentHashDomain, content)),
		size:       int64(len(content)),
		content:    &slowRemoteTargetTestReaderAt{content: content},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := segment.ValidateContext(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(started), 100*time.Millisecond)
}

type slowRemoteTargetTestReaderAt struct {
	content []byte
}

func (this *slowRemoteTargetTestReaderAt) ReadAt(target []byte, offset int64) (int, error) {
	time.Sleep(2 * time.Millisecond)
	if offset >= int64(len(this.content)) {
		return 0, io.EOF
	}
	target[0] = this.content[offset]
	if offset+1 == int64(len(this.content)) {
		return 1, io.EOF
	}
	return 1, nil
}

func validRemoteTargetTestSegment() SealedSegment {
	content := []byte("sealed segment")
	segment, err := newSealedSegment(
		ProducerId{1},
		42,
		SegmentHash(hashJournalBytes(journalSegmentHashDomain, content)),
		int64(len(content)),
		bytes.NewReader(content),
	)
	if err != nil {
		panic(err)
	}
	return segment
}

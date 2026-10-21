package recording

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	cli "github.com/echocat/cli4g"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/cli/format"
	"github.com/engity-com/bifroest/pkg/cli/transport"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	bfRecording "github.com/engity-com/bifroest/pkg/recording"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestRecordingListVerifiesOnlyRequestedPage(t *testing.T) {
	fixture := createRecordingFixture(t)
	conf, input := configureRecordingFixture(t, fixture)
	const corruptID = "ffffffff-ffff-4fff-bfff-ffffffffffff"
	require.Less(t, fixture.id.String(), corruptID)
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(input), corruptID+".bcast"), []byte("corrupt artifact"), 0600))
	app := newRecordingTestApplication(t)
	var output bytes.Buffer
	ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
	opts := &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}
	args := []string{"recording", "ls", "default", "--configuration=" + conf.Filename, "--format=json", "--limit=1"}
	require.NoError(t, app.ParseAndExecute(ctx, opts, args...))
	var rows []RecordingView
	require.NoError(t, json.Unmarshal(output.Bytes(), &rows))
	require.Len(t, rows, 1)
	require.Equal(t, fixture.id.String(), rows[0].ID)
	output.Reset()
	err := app.ParseAndExecute(ctx, opts, append(args, "--after="+fixture.id.String())...)
	require.Error(t, err, "the selected corrupt artifact must be rejected")
	require.Empty(t, output.String())
	output.Reset()
	err = app.ParseAndExecute(ctx, opts, "recording", "ls", "default", "--configuration="+conf.Filename, "--format=json", "--limit=2")
	require.Error(t, err)
	require.Contains(t, output.String(), fixture.id.String(), "only the verified prefix may be emitted")
	require.NotContains(t, output.String(), corruptID)
	require.False(t, json.Valid(output.Bytes()), "a failed stream must not be completed as a successful JSON result")
}

func recordingPageFixture(t *testing.T, count int) (*configuration.Configuration, []bfRecording.Id) {
	t.Helper()
	fixture := createRecordingFixture(t)
	conf, original := configureRecordingFixture(t, fixture)
	require.NoError(t, os.Remove(original))
	ids := make([]bfRecording.Id, 0, count)
	for i := range count {
		var id bfRecording.Id
		require.NoError(t, id.UnmarshalText([]byte(fmt.Sprintf("%08x-0000-4000-8000-000000000000", i+1))))
		ids = append(ids, id)
		// Start times deliberately run in the opposite order to the ID cursor.
		started := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC).Add(-time.Duration(i) * time.Minute)
		connectionID, err := connection.NewId()
		require.NoError(t, err)
		sessionID, err := session.NewId()
		require.NoError(t, err)
		metadata := bfRecording.CastMetadata{
			RecordingId: id, ConnectionId: connectionID, SessionId: sessionID, OperationId: uuid.New(),
			Flow: "test", Task: audit.SessionTaskExec, ProducerId: fixture.identity.ProducerId(), StartedAt: started,
		}
		var content bytes.Buffer
		writer, err := bfRecording.NewNativeRecordingWriter(&content, fixture.identity, nil,
			bfRecording.CastHeader{Version: 3, Terminal: bfRecording.CastTerminal{Columns: 80, Rows: 24}, Timestamp: started.Unix()},
			metadata, 300, bfRecording.NativeRecordingWriterLimits{})
		require.NoError(t, err)
		exit := uint32(0)
		_, err = writer.Seal(time.Second, bfRecording.CastResult{Status: bfRecording.CastStatusCompleted, EndedAt: started.Add(time.Second)}, &exit)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(original), id.String()+".bcast"), content.Bytes(), 0600))
	}
	return conf, ids
}

func TestRecordingListDefaultLimitAndIDCursor(t *testing.T) {
	defaultSize := int(bfRecording.DefaultSealedPageSize)
	conf, ids := recordingPageFixture(t, defaultSize+5)
	app := newRecordingTestApplication(t)
	for _, test := range []struct {
		flags []string
		want  []bfRecording.Id
	}{
		{nil, ids[:defaultSize]},
		{[]string{"--after=" + ids[defaultSize-1].String()}, ids[defaultSize:]},
		{[]string{"--after=" + ids[1].String(), "--limit=3"}, ids[2:5]},
		{[]string{"--after=" + ids[len(ids)-1].String()}, []bfRecording.Id{}},
		{[]string{"--limit=1000"}, ids},
	} {
		var output bytes.Buffer
		ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
		args := []string{"recording", "ls", "default", "--configuration=" + conf.Filename, "--format=json"}
		require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, append(args, test.flags...)...))
		var rows []RecordingView
		require.NoError(t, json.Unmarshal(output.Bytes(), &rows))
		require.Len(t, rows, len(test.want))
		for i, id := range test.want {
			require.Equal(t, id.String(), rows[i].ID)
			require.Equal(t, "full", rows[i].VerificationScope)
		}
	}
}

func TestRecordingListPageFormatsAndInvalidOptions(t *testing.T) {
	conf, ids := recordingPageFixture(t, 3)
	app := newRecordingTestApplication(t)
	for _, selected := range []format.Format{format.Text, format.Json, format.Yaml, format.Cbor} {
		var output bytes.Buffer
		ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
		args := []string{"recording", "ls", "default", "--configuration=" + conf.Filename, "--format=" + string(selected), "--limit=1", "--after=" + ids[0].String()}
		require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileExecutable}}, args...))
		if selected == format.Text {
			require.Contains(t, output.String(), ids[1].String())
			require.NotContains(t, output.String(), ids[0].String())
			require.NotContains(t, output.String(), ids[2].String())
			continue
		}
		var rows []RecordingView
		switch selected {
		case format.Json:
			require.NoError(t, json.Unmarshal(output.Bytes(), &rows))
		case format.Yaml:
			require.NoError(t, yaml.Unmarshal(output.Bytes(), &rows))
		case format.Cbor:
			require.NoError(t, cbor.Unmarshal(output.Bytes(), &rows))
		}
		require.Len(t, rows, 1)
		require.Equal(t, ids[1].String(), rows[0].ID)
	}
	for _, profile := range []string{common.ProfileExecutable, common.ProfileManagement, common.ProfileRemote} {
		for _, flag := range []string{"--limit=0", "--limit=-1", "--limit=1001", "--limit=18446744073709551615", "--after=invalid", "--after=00000000-0000-0000-0000-000000000000"} {
			var output bytes.Buffer
			ctx := cli.ContextWithStdio(t.Context(), nil, &output, nil)
			require.Error(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{profile}}, "recording", "ls", "default", flag))
			require.Empty(t, output.String())
		}
		var help bytes.Buffer
		ctx := cli.ContextWithStdio(t.Context(), nil, &help, nil)
		require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{profile}}, "recording", "ls", "--help"))
		require.NotContains(t, help.String(), "--stream")
		help.Reset()
		require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{profile}}, "recording", "show", "--help"))
		require.NotContains(t, help.String(), "--limit")
		require.NotContains(t, help.String(), "--after")
		require.NotContains(t, help.String(), "--stream")
	}
}

type recordingPageTestBrowser struct {
	options bfRecording.SealedPageOptions
	rows    []RecordingView
}

func (this *recordingPageTestBrowser) Visit(_ context.Context, _ configuration.AuditlogName, options bfRecording.SealedPageOptions, consume func(RecordingView) error) error {
	this.options = options
	for _, row := range this.rows {
		if err := consume(row); err != nil {
			return err
		}
	}
	return nil
}

func (*recordingPageTestBrowser) Detail(context.Context, configuration.AuditlogName, bfRecording.Id) (RecordingView, error) {
	return RecordingView{}, fmt.Errorf("unexpected detail request")
}

func TestManagementRecordingListForwardsPageOptionsAndWireFormat(t *testing.T) {
	app := newRecordingTestApplication(t)
	var after bfRecording.Id
	require.NoError(t, after.UnmarshalText([]byte("00000001-0000-4000-8000-000000000000")))
	browser := &recordingPageTestBrowser{rows: []RecordingView{{ID: "00000002-0000-4000-8000-000000000000"}, {ID: "00000003-0000-4000-8000-000000000000"}}}
	var output bytes.Buffer
	ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{Recordings: browser, WireFormat: true, WireStream: true})
	ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
	require.NoError(t, app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileManagement}},
		"recording", "ls", "default", "--limit=2", "--after="+after.String()))
	require.Equal(t, bfRecording.SealedPageOptions{Limit: 2, After: after}, browser.options)
	var rows []RecordingView
	require.NoError(t, transport.DecodeRecordingListStream(bytes.NewReader(output.Bytes()), func(entry RecordingView) error {
		rows = append(rows, entry)
		return nil
	}))
	require.Len(t, rows, 2)
	require.Less(t, rows[0].ID, rows[1].ID)
}

func TestManagementRecordingListRejectsSingleResponseBeforeReadingRepository(t *testing.T) {
	app := newRecordingTestApplication(t)
	browser := &recordingPageTestBrowser{}
	var output bytes.Buffer
	ctx := common.ContextWithManagementAccess(t.Context(), common.ManagementAccess{Recordings: browser, WireFormat: true})
	ctx = cli.ContextWithStdio(ctx, nil, &output, nil)
	err := app.ParseAndExecute(ctx, &cli.ParseOpts{Profiles: []string{common.ProfileManagement}}, "recording", "ls", "default")
	require.ErrorContains(t, err, "recording ls requires the streaming SSH transport")
	require.Empty(t, output.Bytes())
	require.Equal(t, bfRecording.SealedPageOptions{}, browser.options, "rejected transport must not visit the repository")
}

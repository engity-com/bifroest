package conpty

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPinAndStableSelection(t *testing.T) {
	const baseline = "1.25.261109001"
	pin, err := ParsePin(PinJSON)
	require.NoError(t, err)
	raw, err := pin.Marshal()
	require.NoError(t, err)
	require.Equal(t, PinJSON, raw)
	for _, test := range []struct {
		index, want string
		fail        bool
	}{
		{`{"versions":["1.25.261109001","1.26.261109003-preview","1.25.261110001"]}`, "1.25.261110001", false},
		{`{"versions":["1.24.260710001"]}`, baseline, false},
		{`{"versions":["1.26.261109003-preview"]}`, "", true},
		{`{"versions":["not-a-version"]}`, "", true},
		{`{"versions":["1.25.261110001+metadata"]}`, "", true},
		{`{}`, "", true},
	} {
		actual, err := LatestStable(baseline, []byte(test.index))
		if test.fail {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			require.Equal(t, test.want, actual)
		}
	}
	for _, raw := range [][]byte{
		append(bytes.Clone(PinJSON), []byte(` {}`)...),
		bytes.Replace(PinJSON, []byte(`"version"`), []byte(`"unexpected"`), 1),
		bytes.Replace(PinJSON, []byte(Version), []byte("1.25.261109001-preview"), 1),
		bytes.Replace(PinJSON, []byte(PackageSHA256), []byte("invalid"), 1),
		bytes.Replace(PinJSON, []byte(`"amd64"`), []byte(`"386"`), 1),
	} {
		_, err := ParsePin(raw)
		require.Error(t, err)
	}
}

func TestInspectPackageRequiresIdentityLicenseEveryMachineAndPinnedDigest(t *testing.T) {
	entries := map[string][]byte{Name + ".nuspec": []byte(fmt.Sprintf(`<package><metadata><id>%s</id><version>%s</version><license type="expression">MIT</license></metadata></package>`, Name, Version))}
	for _, payload := range Payloads {
		raw, err := os.ReadFile(payload.Filename())
		require.NoError(t, err)
		entries[payload.Source] = raw
	}
	makePackage := func(entries map[string][]byte, duplicate string) []byte {
		var raw bytes.Buffer
		archive := zip.NewWriter(&raw)
		for name, data := range entries {
			file, err := archive.Create(name)
			require.NoError(t, err)
			_, err = file.Write(data)
			require.NoError(t, err)
		}
		if duplicate != "" {
			_, err := archive.Create(duplicate)
			require.NoError(t, err)
		}
		require.NoError(t, archive.Close())
		return raw.Bytes()
	}
	raw := makePackage(entries, "")
	pin, files, err := InspectPackage(Version, raw, "")
	require.NoError(t, err)
	require.Len(t, files, 3)
	_, _, err = InspectPackage(Version, raw, pin.PackageSHA256)
	require.NoError(t, err)
	_, _, err = InspectPackage(Version, raw, strings.Repeat("0", 64))
	require.ErrorContains(t, err, "digest mismatch")
	_, _, err = InspectPackage(Version, makePackage(entries, Payloads[0].Source), "")
	require.ErrorContains(t, err, "duplicate")
	for _, bad := range []string{"license", "identity", "version", "missing architecture", "wrong machine"} {
		t.Run(bad, func(t *testing.T) {
			changed := make(map[string][]byte)
			for key, value := range entries {
				changed[key] = bytes.Clone(value)
			}
			switch bad {
			case "license":
				changed[Name+".nuspec"] = bytes.Replace(changed[Name+".nuspec"], []byte("MIT"), []byte("Other"), 1)
			case "identity":
				changed[Name+".nuspec"] = bytes.Replace(changed[Name+".nuspec"], []byte(Name), []byte("Other.Package"), 1)
			case "version":
				changed[Name+".nuspec"] = bytes.Replace(changed[Name+".nuspec"], []byte(Version), []byte("0.0.0"), 1)
			case "missing architecture":
				delete(changed, Payloads[2].Source)
			case "wrong machine":
				changed[Payloads[1].Source] = changed[Payloads[0].Source]
			}
			_, files, err := InspectPackage(Version, makePackage(changed, ""), "")
			require.Error(t, err)
			require.Nil(t, files, "failed validation must not return a partial update")
		})
	}
}

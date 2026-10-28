// Package browserfixture holds test-only observations from a real Windows
// process. These records are not an authentication or management protocol.
package browserfixture

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

const Prefix = "BIFROEST_NATIVE_PROBE="
const Suffix = ";ENDPROBE"
const Flow = "native-windows-browser"

type Fixture struct {
	Service     string `json:"service"`
	Root        string `json:"root"`
	User        string `json:"user"`
	SID         string `json:"sid"`
	Probe       string `json:"probe"`
	Producer    string `json:"producer"`
	Certificate string `json:"certificate"`
	HostKey     string `json:"hostKey"`
}

type Probe struct {
	Marker         string `json:"marker"`
	Session        string `json:"session"`
	Connection     string `json:"connection"`
	Execution      string `json:"execution"`
	SID            string `json:"sid"`
	User           string `json:"user"`
	Profile        string `json:"profile"`
	PID            int    `json:"pid"`
	Pty            bool   `json:"pty"`
	Columns        int    `json:"columns"`
	Rows           int    `json:"rows"`
	Content        string `json:"content"`
	Term           string `json:"term"`
	StdinPty       bool   `json:"stdinPty"`
	StdoutError    string `json:"stdoutError"`
	Console        bool   `json:"console"`
	ConsoleColumns int    `json:"consoleColumns"`
	ConsoleRows    int    `json:"consoleRows"`
}

func Encode(probe Probe) (string, error) {
	raw, err := json.Marshal(probe)
	if err != nil {
		return "", err
	}
	return Prefix + base64.StdEncoding.EncodeToString(raw) + Suffix, nil
}

var probePattern = regexp.MustCompile(regexp.QuoteMeta(Prefix) + `([A-Za-z0-9+/=]+)` + regexp.QuoteMeta(Suffix))

func Decode(output, marker string) (Probe, error) {
	var result Probe
	found := false
	for _, match := range probePattern.FindAllStringSubmatch(output, -1) {
		raw, err := base64.StdEncoding.Strict().DecodeString(match[1])
		if err != nil || base64.StdEncoding.EncodeToString(raw) != match[1] {
			return result, fmt.Errorf("invalid native probe encoding")
		}
		var probe Probe
		if err := json.Unmarshal(raw, &probe); err != nil {
			return result, err
		}
		if probe.Marker != marker {
			continue
		}
		if found {
			return Probe{}, fmt.Errorf("duplicate native probe marker")
		}
		found, result = true, probe
	}
	if !found {
		return Probe{}, fmt.Errorf("missing native probe %q", marker)
	}
	return result, nil
}

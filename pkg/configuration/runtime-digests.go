package configuration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"gopkg.in/yaml.v3"
)

// RuntimeFlowDigests are private comparisons, never authentication proofs or
// content-addressed revision identities. Random revisions still change when
// configuration changes back to earlier values.
type RuntimeFlowDigests struct {
	Environment string
	Owner       string
}

// RuntimeDigests hashes the effective definitions, including referenced root
// values. The key belongs to the private session store, not YAML or a log. Only
// digests leave this method; no additional configuration/credential copy is saved.
// External files and runtime-dependent template values are not read/rendered:
// equality alone never authorizes reuse or reconstructs an old provider.
func (this *Snapshot) RuntimeDigests(key []byte) (map[FlowName]RuntimeFlowDigests, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("runtime comparison requires a 32-byte private key")
	}
	conf := this.Configuration()
	result := make(map[FlowName]RuntimeFlowDigests, len(conf.Flows))
	digest := func(domain string, value any) (string, error) {
		raw, err := yaml.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("cannot encode effective runtime definition")
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte("bifroest-runtime-comparison-v1\x00" + domain + "\x00"))
		_, _ = mac.Write(raw)
		return hex.EncodeToString(mac.Sum(nil)), nil
	}
	for _, flow := range conf.Flows {
		flow = flowWithoutPresentation(flow)
		flow.Authorization.Reference, flow.Authorization.resolved = "", false
		flow.Environment.Reference, flow.Environment.resolved = "", false
		environment, err := digest("environment", flow.Environment)
		if err != nil {
			return nil, err
		}
		var auditlog *Auditlog
		for index := range conf.Auditlogs {
			if conf.Auditlogs[index].Name == flow.Auditlog {
				auditlog = &conf.Auditlogs[index]
				break
			}
		}
		owner, err := digest("owner", struct {
			Flow     Flow      `yaml:"flow"`
			Auditlog *Auditlog `yaml:"auditlog"`
		}{flow, auditlog})
		if err != nil {
			return nil, err
		}
		result[flow.Name] = RuntimeFlowDigests{Environment: environment, Owner: owner}
	}
	return result, nil
}

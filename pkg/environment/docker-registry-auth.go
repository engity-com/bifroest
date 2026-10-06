package environment

import (
	"encoding/base64"
	"encoding/json"

	"github.com/moby/moby/api/types/registry"
)

func decodeDockerAuthConfig(encoded string) (*registry.AuthConfig, error) {
	data, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var config registry.AuthConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func encodeDockerAuthConfig(config registry.AuthConfig) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(data), nil
}

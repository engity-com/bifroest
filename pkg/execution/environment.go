package execution

import (
	"encoding/base64"
	"encoding/json"
)

const TargetEnvironmentEnvName = "BIFROEST_TARGET_ENVIRONMENT"

func EncodeTargetEnvironment(environment map[string]string) (string, error) {
	plain, err := json.Marshal(environment)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(plain), nil
}

func DecodeTargetEnvironment(encoded string) (map[string]string, error) {
	plain, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var result map[string]string
	if err := json.Unmarshal(plain, &result); err != nil {
		return nil, err
	}
	if result == nil {
		result = make(map[string]string)
	}
	return result, nil
}

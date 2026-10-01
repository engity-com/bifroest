//go:build unix && !darwin

package configuration

type EnvironmentLocalPlatform struct{}

func (*EnvironmentLocalPlatform) SetDefaults() error { return nil }
func (*EnvironmentLocalPlatform) Trim() error        { return nil }
func (*EnvironmentLocalPlatform) Validate() error    { return nil }

func (EnvironmentLocalPlatform) IsEqualTo(other any) bool {
	switch other.(type) {
	case EnvironmentLocalPlatform, *EnvironmentLocalPlatform:
		return true
	default:
		return false
	}
}

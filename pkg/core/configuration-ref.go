package core

func NewConfigurationRef(plain string) (ConfigurationRef, error) {
	var buf ConfigurationRef
	if err := buf.Set(plain); err != nil {
		return ConfigurationRef{}, nil
	}
	return buf, nil
}

type ConfigurationRef struct {
	v  Configuration
	fn string
}

func (this ConfigurationRef) IsZero() bool {
	return len(this.fn) == 0
}

func (this ConfigurationRef) MarshalText() (text []byte, err error) {
	return []byte(this.String()), nil
}

func (this ConfigurationRef) String() string {
	return this.fn
}

func (this *ConfigurationRef) UnmarshalText(text []byte) error {
	buf := ConfigurationRef{
		fn: string(text),
	}

	if len(buf.fn) > 0 {
		if err := buf.v.LoadFromFile(buf.fn); err != nil {
			return err
		}
	}

	*this = buf
	return nil
}

func (this *ConfigurationRef) Set(text string) error {
	return this.UnmarshalText([]byte(text))
}

func (this *ConfigurationRef) Get() *Configuration {
	return &this.v
}

func (this *ConfigurationRef) GetFilename() string {
	return this.fn
}

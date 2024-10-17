package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultAlternativesDownloadUrl = template.MustNewUrl("https://github.com/engity-com/bifroest/releases/download/v{{.version}}/bifroest-{{.os}}-{{.arch}}-generic{{.packageExt}}")
	DefaultAlternativesLocation    = template.MustNewString(defaultAlternativesLocation)
)

type Alternatives struct {
	DownloadUrl template.Url    `yaml:"downloadUrl,omitempty"`
	Location    template.String `yaml:"location,omitempty"`
}

func (this *Alternatives) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("downloadUrl", func(v *Alternatives) *template.Url { return &v.DownloadUrl }, DefaultAlternativesDownloadUrl),
		fixedDefault("location", func(v *Alternatives) *template.String { return &v.Location }, DefaultAlternativesLocation),
	)
}

func (this *Alternatives) Trim() error {
	return trim(this,
		noopTrim[Alternatives]("downloadUrl"),
		noopTrim[Alternatives]("location"),
	)
}

func (this *Alternatives) Validate() error {
	return validate(this,
		func(v *Alternatives) (string, validator) { return "downloadUrl", &v.DownloadUrl },
		func(v *Alternatives) (string, validator) { return "location", &v.Location },
	)
}

func (this *Alternatives) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *Alternatives, node *yaml.Node) error {
		type raw Alternatives
		return node.Decode((*raw)(target))
	})
}

func (this Alternatives) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Alternatives:
		return this.isEqualTo(&v)
	case *Alternatives:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Alternatives) isEqualTo(other *Alternatives) bool {
	return isEqual(&this.DownloadUrl, &other.DownloadUrl) &&
		isEqual(&this.Location, &other.Location)
}

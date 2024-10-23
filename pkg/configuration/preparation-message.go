package configuration

import (
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultPreparationMessageId     = common.MustNewRegexp(`.*`)
	DefaultPreparationMessageFlow   = common.MustNewRegexp(`.*`)
	DefaultPreparationMessageStart  = template.MustNewString("{{.title}}...")
	DefaultPreparationMessageUpdate = template.MustNewString("\r{{.title}}... {{.percentage | printf `%.0f%%`}}")
	DefaultPreparationMessageEnd    = template.MustNewString("\r{{.title}}... DONE!\n")
	DefaultPreparationMessageError  = template.MustNewString("\r{{.title}}... FAILED! Contact server operator for more information. Disconnecting now...\n")
)

type PreparationMessage struct {
	Id   common.Regexp `yaml:"id,omitempty"`
	Flow common.Regexp `yaml:"flow,omitempty"`

	Start  template.String `yaml:"start,omitempty"`
	Update template.String `yaml:"update,omitempty"`
	End    template.String `yaml:"end,omitempty"`
	Error  template.String `yaml:"error,omitempty"`
}

func (this *PreparationMessage) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("id", func(v *PreparationMessage) *common.Regexp { return &v.Id }, DefaultPreparationMessageId),
		fixedDefault("flow", func(v *PreparationMessage) *common.Regexp { return &v.Flow }, DefaultPreparationMessageFlow),

		fixedDefault("start", func(v *PreparationMessage) *template.String { return &v.Start }, DefaultPreparationMessageStart),
		fixedDefault("update", func(v *PreparationMessage) *template.String { return &v.Update }, DefaultPreparationMessageUpdate),
		fixedDefault("end", func(v *PreparationMessage) *template.String { return &v.End }, DefaultPreparationMessageEnd),
		fixedDefault("error", func(v *PreparationMessage) *template.String { return &v.Error }, DefaultPreparationMessageError),
	)
}

func (this *PreparationMessage) Trim() error {
	return trim(this,
		noopTrim[PreparationMessage]("id"),
		noopTrim[PreparationMessage]("flow"),

		noopTrim[PreparationMessage]("start"),
		noopTrim[PreparationMessage]("update"),
		noopTrim[PreparationMessage]("end"),
		noopTrim[PreparationMessage]("error"),
	)
}

func (this *PreparationMessage) Validate() error {
	return validate(this,
		func(v *PreparationMessage) (string, validator) { return "id", &v.Id },
		func(v *PreparationMessage) (string, validator) { return "flow", &v.Flow },

		func(v *PreparationMessage) (string, validator) { return "start", &v.Start },
		func(v *PreparationMessage) (string, validator) { return "update", &v.Update },
		func(v *PreparationMessage) (string, validator) { return "end", &v.End },
		func(v *PreparationMessage) (string, validator) { return "error", &v.Error },
	)
}

func (this *PreparationMessage) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *PreparationMessage, node *yaml.Node) error {
		type raw PreparationMessage
		return node.Decode((*raw)(target))
	})
}

func (this PreparationMessage) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PreparationMessage:
		return this.isEqualTo(&v)
	case *PreparationMessage:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PreparationMessage) isEqualTo(other *PreparationMessage) bool {
	return isEqual(&this.Id, &other.Id) &&
		isEqual(&this.Flow, &other.Flow) &&
		isEqual(&this.Start, &other.Start) &&
		isEqual(&this.Update, &other.Update) &&
		isEqual(&this.End, &other.End) &&
		isEqual(&this.Error, &other.Error)
}

// PreparationMessages defines a set of PreparationMessage instances.
type PreparationMessages []PreparationMessage

func (this *PreparationMessages) SetDefaults() error {
	return setSliceDefaults(this, PreparationMessage{}) // Has one entry, be default.
}

func (this *PreparationMessages) Trim() error {
	return trimSlice(this)
}

func (this PreparationMessages) Validate() error {
	return validateSlice(this)
}

func (this *PreparationMessages) UnmarshalYAML(node *yaml.Node) error {
	// Clear the entries before...
	*this = PreparationMessages{}
	return unmarshalYAML(this, node, func(target *PreparationMessages, node *yaml.Node) error {
		type raw PreparationMessages
		return node.Decode((*raw)(target))
	})
}

func (this PreparationMessages) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case PreparationMessages:
		return this.isEqualTo(&v)
	case *PreparationMessages:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this PreparationMessages) isEqualTo(other *PreparationMessages) bool {
	if len(this) != len(*other) {
		return false
	}
	for i, tv := range this {
		if !tv.IsEqualTo((*other)[i]) {
			return false
		}
	}
	return true
}

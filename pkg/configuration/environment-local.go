package configuration

import "github.com/engity-com/bifroest/pkg/template"

var (
	DefaultEnvironmentLocalLoginAllowed               = template.BoolOf(true)
	DefaultEnvironmentLocalBanner                     = template.MustNewString("")
	DefaultEnvironmentLocalPortForwardingAllowed      = template.BoolOf(true)
	DefaultEnvironmentLocalManagedGroup               = "bifroest-managed"
	DefaultEnvironmentLocalManageSystemUsers          = template.BoolOf(false)
	DefaultEnvironmentLocalCreateIfAbsent             = template.BoolOf(false)
	DefaultEnvironmentLocalUpdateIfDifferent          = template.BoolOf(false)
	DefaultEnvironmentLocalDeleteOnDispose            = template.BoolOf(false)
	DefaultEnvironmentLocalDeleteHomeTogetherWithUser = template.BoolOf(true)
	DefaultEnvironmentLocalKillProcessesOnDispose     = template.MustNewBool("{{ .user.managed }}")

	_ = RegisterEnvironmentV(func() EnvironmentV {
		return &EnvironmentLocal{}
	})
)

type EnvironmentLocalCommon struct {
	LoginAllowed               template.Bool           `yaml:"loginAllowed,omitempty"`
	CreateIfAbsent             template.Bool           `yaml:"createIfAbsent,omitempty"`
	UpdateIfDifferent          template.Bool           `yaml:"updateIfDifferent,omitempty"`
	ManagedGroup               string                  `yaml:"managedGroup,omitempty"`
	ManageSystemUsers          template.Bool           `yaml:"manageSystemUsers,omitempty"`
	DeleteOnDispose            template.Bool           `yaml:"deleteOnDispose,omitempty"`
	DeleteHomeTogetherWithUser template.Bool           `yaml:"deleteHomeTogetherWithUser,omitempty"`
	KillProcessesOnDispose     template.Bool           `yaml:"killProcessesOnDispose,omitempty"`
	Dispose                    EnvironmentLocalDispose `yaml:"dispose,omitempty"`
	Banner                     template.String         `yaml:"banner,omitempty"`
	PortForwardingAllowed      template.Bool           `yaml:"portForwardingAllowed,omitempty"`
	ShellCommand               template.Strings        `yaml:"shellCommand,omitempty"`
	ExecCommandPrefix          template.Strings        `yaml:"execCommandPrefix,omitempty"`
	Directory                  template.String         `yaml:"directory,omitempty"`
}

func (this *EnvironmentLocalCommon) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("loginAllowed", func(v *EnvironmentLocalCommon) *template.Bool { return &v.LoginAllowed }, DefaultEnvironmentLocalLoginAllowed),
		fixedDefault("createIfAbsent", func(v *EnvironmentLocalCommon) *template.Bool { return &v.CreateIfAbsent }, DefaultEnvironmentLocalCreateIfAbsent),
		fixedDefault("updateIfDifferent", func(v *EnvironmentLocalCommon) *template.Bool { return &v.UpdateIfDifferent }, DefaultEnvironmentLocalUpdateIfDifferent),
		fixedDefault("managedGroup", func(v *EnvironmentLocalCommon) *string { return &v.ManagedGroup }, DefaultEnvironmentLocalManagedGroup),
		fixedDefault("manageSystemUsers", func(v *EnvironmentLocalCommon) *template.Bool { return &v.ManageSystemUsers }, DefaultEnvironmentLocalManageSystemUsers),
		fixedDefault("deleteOnDispose", func(v *EnvironmentLocalCommon) *template.Bool { return &v.DeleteOnDispose }, DefaultEnvironmentLocalDeleteOnDispose),
		fixedDefault("deleteHomeTogetherWithUser", func(v *EnvironmentLocalCommon) *template.Bool { return &v.DeleteHomeTogetherWithUser }, DefaultEnvironmentLocalDeleteHomeTogetherWithUser),
		fixedDefault("killProcessesOnDispose", func(v *EnvironmentLocalCommon) *template.Bool { return &v.KillProcessesOnDispose }, DefaultEnvironmentLocalKillProcessesOnDispose),
		func(v *EnvironmentLocalCommon) (string, defaulter) { return "dispose", &v.Dispose },
		fixedDefault("banner", func(v *EnvironmentLocalCommon) *template.String { return &v.Banner }, DefaultEnvironmentLocalBanner),
		fixedDefault("portForwardingAllowed", func(v *EnvironmentLocalCommon) *template.Bool { return &v.PortForwardingAllowed }, DefaultEnvironmentLocalPortForwardingAllowed),
		fixedDefault("shellCommand", func(v *EnvironmentLocalCommon) *template.Strings { return &v.ShellCommand }, DefaultEnvironmentLocalShellCommand),
		fixedDefault("execCommandPrefix", func(v *EnvironmentLocalCommon) *template.Strings { return &v.ExecCommandPrefix }, DefaultEnvironmentLocalExecCommandPrefix),
		fixedDefault("directory", func(v *EnvironmentLocalCommon) *template.String { return &v.Directory }, DefaultEnvironmentLocalDirectory),
	)
}

func (this *EnvironmentLocalCommon) Trim() error {
	return trim(this,
		noopTrim[EnvironmentLocalCommon]("loginAllowed"),
		noopTrim[EnvironmentLocalCommon]("createIfAbsent"),
		noopTrim[EnvironmentLocalCommon]("updateIfDifferent"),
		noopTrim[EnvironmentLocalCommon]("managedGroup"),
		noopTrim[EnvironmentLocalCommon]("manageSystemUsers"),
		noopTrim[EnvironmentLocalCommon]("deleteOnDispose"),
		noopTrim[EnvironmentLocalCommon]("deleteHomeTogetherWithUser"),
		noopTrim[EnvironmentLocalCommon]("killProcessesOnDispose"),
		func(v *EnvironmentLocalCommon) (string, trimmer) { return "dispose", &v.Dispose },
		noopTrim[EnvironmentLocalCommon]("banner"),
		noopTrim[EnvironmentLocalCommon]("portForwardingAllowed"),
		noopTrim[EnvironmentLocalCommon]("shellCommand"),
		noopTrim[EnvironmentLocalCommon]("execCommandPrefix"),
		noopTrim[EnvironmentLocalCommon]("directory"),
	)
}

func (this *EnvironmentLocalCommon) Validate() error {
	return validate(this,
		func(v *EnvironmentLocalCommon) (string, validator) { return "loginAllowed", &v.LoginAllowed },
		func(v *EnvironmentLocalCommon) (string, validator) { return "createIfAbsent", &v.CreateIfAbsent },
		func(v *EnvironmentLocalCommon) (string, validator) { return "updateIfDifferent", &v.UpdateIfDifferent },
		notEmptyStringValidate("managedGroup", func(v *EnvironmentLocalCommon) *string { return &v.ManagedGroup }),
		func(v *EnvironmentLocalCommon) (string, validator) { return "manageSystemUsers", &v.ManageSystemUsers },
		func(v *EnvironmentLocalCommon) (string, validator) { return "deleteOnDispose", &v.DeleteOnDispose },
		func(v *EnvironmentLocalCommon) (string, validator) {
			return "deleteHomeTogetherWithUser", &v.DeleteHomeTogetherWithUser
		},
		func(v *EnvironmentLocalCommon) (string, validator) {
			return "killProcessesOnDispose", &v.KillProcessesOnDispose
		},
		func(v *EnvironmentLocalCommon) (string, validator) { return "dispose", &v.Dispose },
		func(v *EnvironmentLocalCommon) (string, validator) { return "banner", &v.Banner },
		func(v *EnvironmentLocalCommon) (string, validator) {
			return "portForwardingAllowed", &v.PortForwardingAllowed
		},
		func(v *EnvironmentLocalCommon) (string, validator) { return "shellCommand", &v.ShellCommand },
		func(v *EnvironmentLocalCommon) (string, validator) { return "execCommandPrefix", &v.ExecCommandPrefix },
		func(v *EnvironmentLocalCommon) (string, validator) { return "directory", &v.Directory },
	)
}

func (this EnvironmentLocalCommon) IsEqualTo(other any) bool {
	switch v := other.(type) {
	case EnvironmentLocalCommon:
		return this.isEqualTo(&v)
	case *EnvironmentLocalCommon:
		return v != nil && this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentLocalCommon) isEqualTo(other *EnvironmentLocalCommon) bool {
	return isEqual(&this.LoginAllowed, &other.LoginAllowed) &&
		isEqual(&this.CreateIfAbsent, &other.CreateIfAbsent) &&
		isEqual(&this.UpdateIfDifferent, &other.UpdateIfDifferent) &&
		this.ManagedGroup == other.ManagedGroup &&
		isEqual(&this.ManageSystemUsers, &other.ManageSystemUsers) &&
		isEqual(&this.DeleteOnDispose, &other.DeleteOnDispose) &&
		isEqual(&this.DeleteHomeTogetherWithUser, &other.DeleteHomeTogetherWithUser) &&
		isEqual(&this.KillProcessesOnDispose, &other.KillProcessesOnDispose) &&
		isEqual(&this.Dispose, &other.Dispose) &&
		isEqual(&this.Banner, &other.Banner) &&
		isEqual(&this.PortForwardingAllowed, &other.PortForwardingAllowed) &&
		isEqual(&this.ShellCommand, &other.ShellCommand) &&
		isEqual(&this.ExecCommandPrefix, &other.ExecCommandPrefix) &&
		isEqual(&this.Directory, &other.Directory)
}

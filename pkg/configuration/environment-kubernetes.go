package configuration

import (
	"time"

	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/kubernetes"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

var (
	DefaultEnvironmentKubernetesLoginAllowed = template.BoolOf(true)

	DefaultEnvironmentKubernetesConfig  = kubernetes.MustNewKubeconfig("")
	DefaultEnvironmentKubernetesContext = ""

	DefaultEnvironmentKubernetesName                 = template.MustNewString("bifroest-{{.session.id}}")
	DefaultEnvironmentKubernetesNamespace            = template.MustNewString("")
	DefaultEnvironmentKubernetesOs                   = sys.OsLinux
	DefaultEnvironmentKubernetesArch                 = sys.ArchAmd64
	DefaultEnvironmentKubernetesServiceAccount       = template.MustNewString("")
	DefaultEnvironmentKubernetesImage                = template.MustNewString("alpine")
	DefaultEnvironmentKubernetesImagePullPolicy      = PullPolicyIfAbsent
	DefaultEnvironmentKubernetesImagePullCredentials = template.MustNewString("")
	DefaultEnvironmentKubernetesImageContextMode     = ContextModeOnline
	DefaultEnvironmentKubernetesReadyTimeout         = template.DurationOf(5 * time.Minute)
	DefaultEnvironmentKubernetesRemoveTimeout        = 1 * time.Minute

	DefaultEnvironmentKubernetesCapabilities = template.MustNewStrings()
	DefaultEnvironmentKubernetesPrivileged   = template.BoolOf(false)
	DefaultEnvironmentKubernetesDnsServers   = template.MustNewStrings()
	DefaultEnvironmentKubernetesDnsSearch    = template.MustNewStrings()
	DefaultEnvironmentKubernetesShellCommand = template.MustNewStrings()
	DefaultEnvironmentKubernetesExecCommand  = template.MustNewStrings()
	DefaultEnvironmentKubernetesSftpCommand  = template.MustNewStrings()
	DefaultEnvironmentKubernetesDirectory    = template.MustNewString("")
	DefaultEnvironmentKubernetesUser         = template.MustNewString("")
	DefaultEnvironmentKubernetesGroup        = template.MustNewString("")

	DefaultEnvironmentKubernetesBanner                = template.MustNewString("")
	DefaultEnvironmentKubernetesPortForwardingAllowed = template.BoolOf(true)

	DefaultEnvironmentKubernetesCleanOrphan = template.BoolOf(true)

	_ = RegisterEnvironmentV(func() EnvironmentV {
		return &EnvironmentKubernetes{}
	})
)

type EnvironmentKubernetes struct {
	LoginAllowed template.Bool `yaml:"loginAllowed,omitempty"`

	Config  kubernetes.Kubeconfig `yaml:"config,omitempty"`
	Context string                `yaml:"context,omitempty"`

	Name                 template.String   `yaml:"name"`
	Namespace            template.String   `yaml:"namespace,omitempty"`
	Os                   sys.Os            `yaml:"os"`
	Arch                 sys.Arch          `yaml:"arch"`
	ServiceAccount       template.String   `yaml:"serviceAccount,omitempty"`
	Image                template.String   `yaml:"image"`
	ImagePullPolicy      PullPolicy        `yaml:"imagePullPolicy,omitempty"`
	ImagePullCredentials template.String   `yaml:"imagePullCredentials,omitempty"`
	ImageContextMode     ContextMode       `yaml:"imageContextMode,omitempty"`
	ReadyTimeout         template.Duration `yaml:"readyTimeout,omitempty"`
	RemoveTimeout        time.Duration     `yaml:"removeTimeout,omitempty"`
	Capabilities         template.Strings  `yaml:"capabilities,omitempty"`
	Privileged           template.Bool     `yaml:"privileged,omitempty"`
	DnsServers           template.Strings  `yaml:"dnsServers,omitempty"`
	DnsSearch            template.Strings  `yaml:"dnsSearch,omitempty"`

	ShellCommand template.Strings `yaml:"shellCommand,omitempty"`
	ExecCommand  template.Strings `yaml:"execCommand,omitempty"`
	SftpCommand  template.Strings `yaml:"sftpCommand,omitempty"`
	Directory    template.String  `yaml:"directory"`
	User         template.String  `yaml:"user,omitempty"`
	Group        template.String  `yaml:"group,omitempty"`

	Banner template.String `yaml:"banner,omitempty"`

	PortForwardingAllowed template.Bool `yaml:"portForwardingAllowed,omitempty"`

	CleanOrphan template.Bool `yaml:"cleanOrphan,omitempty"`
}

func (this *EnvironmentKubernetes) SetDefaults() error {
	return setDefaults(this,
		fixedDefault("loginAllowed", func(v *EnvironmentKubernetes) *template.Bool { return &v.LoginAllowed }, DefaultEnvironmentKubernetesLoginAllowed),

		fixedDefault("config", func(v *EnvironmentKubernetes) *kubernetes.Kubeconfig { return &v.Config }, DefaultEnvironmentKubernetesConfig),
		fixedDefault("context", func(v *EnvironmentKubernetes) *string { return &v.Context }, DefaultEnvironmentKubernetesContext),

		fixedDefault("name", func(v *EnvironmentKubernetes) *template.String { return &v.Name }, DefaultEnvironmentKubernetesName),
		fixedDefault("namespace", func(v *EnvironmentKubernetes) *template.String { return &v.Namespace }, DefaultEnvironmentKubernetesNamespace),
		fixedDefault("os", func(v *EnvironmentKubernetes) *sys.Os { return &v.Os }, DefaultEnvironmentKubernetesOs),
		fixedDefault("arch", func(v *EnvironmentKubernetes) *sys.Arch { return &v.Arch }, DefaultEnvironmentKubernetesArch),
		fixedDefault("serviceAccount", func(v *EnvironmentKubernetes) *template.String { return &v.ServiceAccount }, DefaultEnvironmentKubernetesServiceAccount),
		fixedDefault("image", func(v *EnvironmentKubernetes) *template.String { return &v.Image }, DefaultEnvironmentKubernetesImage),
		fixedDefault("imagePullPolicy", func(v *EnvironmentKubernetes) *PullPolicy { return &v.ImagePullPolicy }, DefaultEnvironmentKubernetesImagePullPolicy),
		fixedDefault("imagePullCredentials", func(v *EnvironmentKubernetes) *template.String { return &v.ImagePullCredentials }, DefaultEnvironmentKubernetesImagePullCredentials),
		fixedDefault("imageContextMode", func(v *EnvironmentKubernetes) *ContextMode { return &v.ImageContextMode }, DefaultEnvironmentKubernetesImageContextMode),
		fixedDefault("readyTimeout", func(v *EnvironmentKubernetes) *template.Duration { return &v.ReadyTimeout }, DefaultEnvironmentKubernetesReadyTimeout),
		fixedDefault("removeTimeout", func(v *EnvironmentKubernetes) *time.Duration { return &v.RemoveTimeout }, DefaultEnvironmentKubernetesRemoveTimeout),
		fixedDefault("capabilities", func(v *EnvironmentKubernetes) *template.Strings { return &v.Capabilities }, DefaultEnvironmentKubernetesCapabilities),
		fixedDefault("privileged", func(v *EnvironmentKubernetes) *template.Bool { return &v.Privileged }, DefaultEnvironmentKubernetesPrivileged),
		fixedDefault("dnsServers", func(v *EnvironmentKubernetes) *template.Strings { return &v.DnsServers }, DefaultEnvironmentKubernetesDnsServers),
		fixedDefault("dnsSearch", func(v *EnvironmentKubernetes) *template.Strings { return &v.DnsSearch }, DefaultEnvironmentKubernetesDnsSearch),

		fixedDefault("shellCommand", func(v *EnvironmentKubernetes) *template.Strings { return &v.ShellCommand }, DefaultEnvironmentKubernetesShellCommand),
		fixedDefault("execCommand", func(v *EnvironmentKubernetes) *template.Strings { return &v.ExecCommand }, DefaultEnvironmentKubernetesExecCommand),
		fixedDefault("sftpCommand", func(v *EnvironmentKubernetes) *template.Strings { return &v.SftpCommand }, DefaultEnvironmentKubernetesSftpCommand),
		fixedDefault("directory", func(v *EnvironmentKubernetes) *template.String { return &v.Directory }, DefaultEnvironmentKubernetesDirectory),
		fixedDefault("user", func(v *EnvironmentKubernetes) *template.String { return &v.User }, DefaultEnvironmentKubernetesUser),
		fixedDefault("group", func(v *EnvironmentKubernetes) *template.String { return &v.Group }, DefaultEnvironmentKubernetesGroup),

		fixedDefault("banner", func(v *EnvironmentKubernetes) *template.String { return &v.Banner }, DefaultEnvironmentKubernetesBanner),

		fixedDefault("portForwardingAllowed", func(v *EnvironmentKubernetes) *template.Bool { return &v.PortForwardingAllowed }, DefaultEnvironmentKubernetesPortForwardingAllowed),

		fixedDefault("cleanOrphan", func(v *EnvironmentKubernetes) *template.Bool { return &v.CleanOrphan }, DefaultEnvironmentKubernetesCleanOrphan),
	)
}

func (this *EnvironmentKubernetes) Trim() error {
	return trim(this,
		noopTrim[EnvironmentKubernetes]("loginAllowed"),

		noopTrim[EnvironmentKubernetes]("config"),
		noopTrim[EnvironmentKubernetes]("context"),

		noopTrim[EnvironmentKubernetes]("name"),
		noopTrim[EnvironmentKubernetes]("namespace"),
		noopTrim[EnvironmentKubernetes]("os"),
		noopTrim[EnvironmentKubernetes]("arch"),
		noopTrim[EnvironmentKubernetes]("serviceAccount"),
		noopTrim[EnvironmentKubernetes]("image"),
		noopTrim[EnvironmentKubernetes]("imagePullPolicy"),
		noopTrim[EnvironmentKubernetes]("imagePullCredentials"),
		noopTrim[EnvironmentKubernetes]("imageContextMode"),
		noopTrim[EnvironmentKubernetes]("readyTimeout"),
		noopTrim[EnvironmentKubernetes]("removeTimeout"),
		noopTrim[EnvironmentKubernetes]("capabilities"),
		noopTrim[EnvironmentKubernetes]("privileged"),
		noopTrim[EnvironmentKubernetes]("dnsServers"),
		noopTrim[EnvironmentKubernetes]("dnsSearch"),
		noopTrim[EnvironmentKubernetes]("shellCommand"),
		noopTrim[EnvironmentKubernetes]("execCommand"),
		noopTrim[EnvironmentKubernetes]("sftpCommand"),
		noopTrim[EnvironmentKubernetes]("directory"),
		noopTrim[EnvironmentKubernetes]("user"),
		noopTrim[EnvironmentKubernetes]("group"),

		noopTrim[EnvironmentKubernetes]("banner"),

		noopTrim[EnvironmentKubernetes]("portForwardingAllowed"),

		noopTrim[EnvironmentKubernetes]("cleanOrphan"),
	)
}

func (this *EnvironmentKubernetes) Validate() error {
	return validate(this,
		func(v *EnvironmentKubernetes) (string, validator) { return "loginAllowed", &v.LoginAllowed },

		func(v *EnvironmentKubernetes) (string, validator) { return "config", &v.Config },
		noopValidate[EnvironmentKubernetes]("context"),

		func(v *EnvironmentKubernetes) (string, validator) { return "name", &v.Name },
		notZeroValidate("name", func(v *EnvironmentKubernetes) *template.String { return &v.Name }),
		func(v *EnvironmentKubernetes) (string, validator) { return "namespace", &v.Namespace },
		func(v *EnvironmentKubernetes) (string, validator) { return "os", &v.Os },
		func(v *EnvironmentKubernetes) (string, validator) { return "arch", &v.Arch },
		func(v *EnvironmentKubernetes) (string, validator) { return "serviceAccount", &v.ServiceAccount },
		func(v *EnvironmentKubernetes) (string, validator) { return "image", &v.Image },
		notZeroValidate("image", func(v *EnvironmentKubernetes) *template.String { return &v.Image }),
		func(v *EnvironmentKubernetes) (string, validator) { return "imagePullPolicy", &v.ImagePullPolicy },
		func(v *EnvironmentKubernetes) (string, validator) {
			return "imagePullCredentials", &v.ImagePullCredentials
		},
		func(v *EnvironmentKubernetes) (string, validator) { return "imageContextMode", &v.ImageContextMode },
		func(v *EnvironmentKubernetes) (string, validator) { return "readyTimeout", &v.ReadyTimeout },
		func(v *EnvironmentKubernetes) (string, validator) {
			return "removeTimeout", validatorFunc(func() error {
				if this.RemoveTimeout == 0 {
					return errors.Config.Newf("empty duration")
				}
				return nil
			})
		},
		func(v *EnvironmentKubernetes) (string, validator) { return "capabilities", &v.Capabilities },
		func(v *EnvironmentKubernetes) (string, validator) { return "privileged", &v.Privileged },
		func(v *EnvironmentKubernetes) (string, validator) { return "dnsServers", &v.DnsServers },
		func(v *EnvironmentKubernetes) (string, validator) { return "dnsSearch", &v.DnsSearch },
		func(v *EnvironmentKubernetes) (string, validator) { return "shellCommand", &v.ShellCommand },
		func(v *EnvironmentKubernetes) (string, validator) { return "execCommand", &v.ExecCommand },
		func(v *EnvironmentKubernetes) (string, validator) { return "sftpCommand", &v.SftpCommand },
		func(v *EnvironmentKubernetes) (string, validator) { return "directory", &v.Directory },
		func(v *EnvironmentKubernetes) (string, validator) { return "user", &v.User },
		func(v *EnvironmentKubernetes) (string, validator) { return "group", &v.Group },

		func(v *EnvironmentKubernetes) (string, validator) { return "banner", &v.Banner },

		func(v *EnvironmentKubernetes) (string, validator) {
			return "portForwardingAllowed", &v.PortForwardingAllowed
		},

		func(v *EnvironmentKubernetes) (string, validator) { return "cleanOrphan", &v.CleanOrphan },
	)
}

func (this *EnvironmentKubernetes) UnmarshalYAML(node *yaml.Node) error {
	return unmarshalYAML(this, node, func(target *EnvironmentKubernetes, node *yaml.Node) error {
		type raw EnvironmentKubernetes
		return node.Decode((*raw)(target))
	})
}

func (this EnvironmentKubernetes) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case EnvironmentKubernetes:
		return this.isEqualTo(&v)
	case *EnvironmentKubernetes:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this EnvironmentKubernetes) isEqualTo(other *EnvironmentKubernetes) bool {
	return isEqual(&this.LoginAllowed, &other.LoginAllowed) &&
		isEqual(&this.Config, &other.Config) &&
		this.Context == other.Context &&
		isEqual(&this.Name, &other.Name) &&
		isEqual(&this.Namespace, &other.Namespace) &&
		isEqual(&this.Os, &other.Os) &&
		isEqual(&this.Arch, &other.Arch) &&
		isEqual(&this.ServiceAccount, &other.ServiceAccount) &&
		isEqual(&this.Image, &other.Image) &&
		isEqual(&this.ImagePullPolicy, &other.ImagePullPolicy) &&
		isEqual(&this.ImagePullCredentials, &other.ImagePullCredentials) &&
		isEqual(&this.ImageContextMode, &other.ImageContextMode) &&
		isEqual(&this.ReadyTimeout, &other.ReadyTimeout) &&
		this.RemoveTimeout == other.RemoveTimeout &&
		isEqual(&this.Capabilities, &other.Capabilities) &&
		isEqual(&this.Privileged, &other.Privileged) &&
		isEqual(&this.DnsServers, &other.DnsServers) &&
		isEqual(&this.DnsSearch, &other.DnsSearch) &&
		isEqual(&this.ShellCommand, &other.ShellCommand) &&
		isEqual(&this.ExecCommand, &other.ExecCommand) &&
		isEqual(&this.SftpCommand, &other.SftpCommand) &&
		isEqual(&this.Directory, &other.Directory) &&
		isEqual(&this.User, &other.User) &&
		isEqual(&this.Group, &other.Group) &&
		isEqual(&this.Banner, &other.Banner) &&
		isEqual(&this.PortForwardingAllowed, &other.PortForwardingAllowed) &&
		isEqual(&this.CleanOrphan, &other.CleanOrphan)
}

func (this EnvironmentKubernetes) Types() []string {
	return []string{"kubernetes"}
}

func (this EnvironmentKubernetes) FeatureFlags() []string {
	return []string{"kubernetes"}
}

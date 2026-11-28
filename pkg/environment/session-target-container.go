package environment

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

// DockerTargetMetadata is explicit backend identity, not a Docker client or a
// request to discover a daemon. Offline callers must supply their own facts.
type DockerTargetMetadata struct {
	Backend string
	Os      sys.Os
	Arch    sys.Arch
}

func (this *DockerRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	backend, ok := this.apiClient.(interface{ DaemonHost() string })
	if !ok {
		return "", errors.System.Newf("docker backend identity is unavailable")
	}
	projection, err := ProjectDockerTarget(ctx, this.conf, DockerTargetMetadata{Backend: backend.DaemonHost(), Os: this.hostOs, Arch: this.hostArch})
	if err != nil {
		return "", err
	}
	return projection.SessionTarget()
}

func (this *DockerRepository) ResolveSessionReuseTarget(ctx Context, previous configuration.Environment) (session.Target, error) {
	before, ok := previous.V.(*configuration.EnvironmentDocker)
	if !ok {
		return this.ResolveSessionTarget(ctx)
	}
	conf := *this.conf
	// An existing container's image cannot change. Every other target field,
	// including daemon, user, mounts and forwarding policy, remains current.
	conf.Image = before.Image
	view := &DockerRepository{conf: &conf, apiClient: this.apiClient, hostOs: this.hostOs, hostArch: this.hostArch}
	return view.ResolveSessionTarget(ctx)
}

// ProjectDockerTarget evaluates exactly the existing session-target selectors.
// It does not inspect images, resolve runtime defaults or read credentials,
// Docker environment variables, TLS files, or the daemon. Context getters and
// template functions still need controlled dependencies for hermetic execution.
func ProjectDockerTarget(ctx Context, conf *configuration.EnvironmentDocker, metadata DockerTargetMetadata) (TargetProjection, error) {
	if metadata.Backend == "" {
		return TargetProjection{}, errors.System.Newf("docker backend identity is unavailable")
	}
	if conf == nil {
		return TargetProjection{}, errors.Config.Newf("docker target configuration is unavailable")
	}
	fields := newTargetProjectionFields(ctx)
	fields.values["backend"] = metadata.Backend
	fields.values["os"] = metadata.Os.String()
	fields.values["arch"] = metadata.Arch.String()
	fields.string("image", &conf.Image)
	fields.string("user", &conf.User)
	fields.string("directory", &conf.Directory)
	fields.strings("networks", &conf.Networks)
	fields.strings("volumes", &conf.Volumes)
	fields.strings("mounts", &conf.Mounts)
	fields.strings("capabilities", &conf.Capabilities)
	fields.strings("dnsServers", &conf.DnsServers)
	fields.strings("dnsSearch", &conf.DnsSearch)
	fields.boolean("privileged", &conf.Privileged)
	fields.boolean("portForwardingAllowed", &conf.PortForwardingAllowed)
	fields.strings("shellCommand", &conf.ShellCommand)
	fields.strings("execCommand", &conf.ExecCommand)
	fields.strings("sftpCommand", &conf.SftpCommand)
	return fields.projection("docker")
}

// KubernetesTargetMetadata contains only the backend identity and its default
// namespace. Namespace is used only when the rendered selector is empty.
type KubernetesTargetMetadata struct {
	Backend   string
	Namespace string
}

func (this *KubernetesRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	if this.client == nil {
		return "", errors.System.Newf("kubernetes backend identity is unavailable")
	}
	conf := this.client.RestConfig()
	if conf == nil || conf.Host == "" {
		return "", errors.System.Newf("kubernetes backend identity is unavailable")
	}
	projection, err := projectKubernetesTarget(ctx, this.conf, conf.Host, this.client.Namespace)
	if err != nil {
		return "", err
	}
	return projection.SessionTarget()
}

func (this *KubernetesRepository) ResolveSessionReuseTarget(ctx Context, previous configuration.Environment) (session.Target, error) {
	before, ok := previous.V.(*configuration.EnvironmentKubernetes)
	if !ok {
		return this.ResolveSessionTarget(ctx)
	}
	conf := *this.conf
	conf.Image = before.Image
	view := &KubernetesRepository{conf: &conf, client: this.client}
	return view.ResolveSessionTarget(ctx)
}

// ProjectKubernetesTarget needs no Kubernetes client or kubeconfig. It projects
// the production session-target selectors using explicitly supplied metadata,
// without resolving credentials, inspecting images or provisioning resources.
// Template functions and context getters remain caller dependencies.
func ProjectKubernetesTarget(ctx Context, conf *configuration.EnvironmentKubernetes, metadata KubernetesTargetMetadata) (TargetProjection, error) {
	return projectKubernetesTarget(ctx, conf, metadata.Backend, func() string { return metadata.Namespace })
}

func projectKubernetesTarget(ctx Context, conf *configuration.EnvironmentKubernetes, backend string, namespace func() string) (TargetProjection, error) {
	if backend == "" {
		return TargetProjection{}, errors.System.Newf("kubernetes backend identity is unavailable")
	}
	if conf == nil {
		return TargetProjection{}, errors.Config.Newf("kubernetes target configuration is unavailable")
	}
	fields := newTargetProjectionFields(ctx)
	fields.values["backend"] = backend
	fields.values["os"] = conf.Os.String()
	fields.values["arch"] = conf.Arch.String()
	fields.string("name", &conf.Name)
	fields.string("namespace", &conf.Namespace)
	if fields.err == nil && fields.values["namespace"] == "" {
		fields.values["namespace"] = namespace()
	}
	fields.string("serviceAccountName", &conf.ServiceAccountName)
	fields.string("image", &conf.Image)
	fields.string("user", &conf.User)
	fields.string("group", &conf.Group)
	fields.string("directory", &conf.Directory)
	fields.strings("capabilities", &conf.Capabilities)
	fields.strings("dnsServers", &conf.DnsServers)
	fields.strings("dnsSearch", &conf.DnsSearch)
	fields.boolean("privileged", &conf.Privileged)
	fields.boolean("portForwardingAllowed", &conf.PortForwardingAllowed)
	fields.strings("shellCommand", &conf.ShellCommand)
	fields.strings("execCommand", &conf.ExecCommand)
	fields.strings("sftpCommand", &conf.SftpCommand)
	return fields.projection("kubernetes")
}

package environment

import (
	"fmt"

	"github.com/engity-com/bifroest/pkg/session"
)

func (this *DockerRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	backend, ok := this.apiClient.(interface{ DaemonHost() string })
	if !ok || backend.DaemonHost() == "" {
		return "", fmt.Errorf("docker backend identity is unavailable")
	}
	fields := newTargetFields(ctx)
	fields.values["backend"] = backend.DaemonHost()
	fields.values["os"] = this.hostOs.String()
	fields.values["arch"] = this.hostArch.String()
	fields.string("image", &this.conf.Image)
	fields.string("user", &this.conf.User)
	fields.string("directory", &this.conf.Directory)
	fields.strings("networks", &this.conf.Networks)
	fields.strings("volumes", &this.conf.Volumes)
	fields.strings("mounts", &this.conf.Mounts)
	fields.strings("capabilities", &this.conf.Capabilities)
	fields.strings("dnsServers", &this.conf.DnsServers)
	fields.strings("dnsSearch", &this.conf.DnsSearch)
	fields.boolean("privileged", &this.conf.Privileged)
	fields.boolean("portForwardingAllowed", &this.conf.PortForwardingAllowed)
	fields.strings("shellCommand", &this.conf.ShellCommand)
	fields.strings("execCommand", &this.conf.ExecCommand)
	fields.strings("sftpCommand", &this.conf.SftpCommand)
	return fields.target("docker")
}

func (this *KubernetesRepository) ResolveSessionTarget(ctx Context) (session.Target, error) {
	if this.client == nil || this.client.RestConfig() == nil || this.client.RestConfig().Host == "" {
		return "", fmt.Errorf("kubernetes backend identity is unavailable")
	}
	fields := newTargetFields(ctx)
	fields.values["backend"] = this.client.RestConfig().Host
	fields.values["os"] = this.conf.Os.String()
	fields.values["arch"] = this.conf.Arch.String()
	fields.string("name", &this.conf.Name)
	fields.string("namespace", &this.conf.Namespace)
	if fields.err == nil && fields.values["namespace"] == "" {
		fields.values["namespace"] = this.client.Namespace()
	}
	fields.string("serviceAccountName", &this.conf.ServiceAccountName)
	fields.string("image", &this.conf.Image)
	fields.string("user", &this.conf.User)
	fields.string("group", &this.conf.Group)
	fields.string("directory", &this.conf.Directory)
	fields.strings("capabilities", &this.conf.Capabilities)
	fields.strings("dnsServers", &this.conf.DnsServers)
	fields.strings("dnsSearch", &this.conf.DnsSearch)
	fields.boolean("privileged", &this.conf.Privileged)
	fields.boolean("portForwardingAllowed", &this.conf.PortForwardingAllowed)
	fields.strings("shellCommand", &this.conf.ShellCommand)
	fields.strings("execCommand", &this.conf.ExecCommand)
	fields.strings("sftpCommand", &this.conf.SftpCommand)
	return fields.target("kubernetes")
}

package kubernetes

import (
	"net"
	"os"
	"os/user"
	"path/filepath"

	"k8s.io/client-go/rest"
)

type kubeconfigOverwrites struct {
	defaultPath string

	serviceHost          string
	serviceTokenFile     string
	serviceRootCaFile    string
	serviceNamespaceFile string
}

func (this kubeconfigOverwrites) resolveDefaultPath() string {
	if v := this.defaultPath; v != "" {
		return v
	}
	if u, err := user.Current(); err == nil {
		return filepath.Join(u.HomeDir, ".kube", "config")
	}
	return filepath.Join(".kube", "config")
}

func (this kubeconfigOverwrites) resolveServiceHost() (string, error) {
	if v := this.serviceHost; v != "" {
		return v, nil
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return "", rest.ErrNotInCluster
	}
	return "https://" + net.JoinHostPort(host, port), nil
}

func (this kubeconfigOverwrites) resolveServiceTokenFile() string {
	if v := this.serviceTokenFile; v != "" {
		return v
	}
	return ServiceTokenFile
}

func (this kubeconfigOverwrites) resolveServiceRootCaFile() string {
	if v := this.serviceRootCaFile; v != "" {
		return v
	}
	return ServiceRootCAFile
}

func (this kubeconfigOverwrites) resolveServiceNamespaceFile() string {
	if v := this.serviceNamespaceFile; v != "" {
		return v
	}
	return ServiceNamespaceFile
}

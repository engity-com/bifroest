package kubernetes

import (
	"net"
	"os"
	"os/user"
	"path/filepath"

	"k8s.io/client-go/rest"

	"github.com/engity-com/bifroest/pkg/errors"
)

type kubeconfigOverwrites struct {
	defaultFile string

	serviceHost          string
	serviceTokenFile     string
	serviceRootCaFile    string
	serviceNamespaceFile string
}

func (this kubeconfigOverwrites) resolveDefaultFile() string {
	if v := this.defaultFile; v != "" {
		return v
	}
	if u, err := user.Current(); err == nil {
		return filepath.Join(u.HomeDir, ".kube", "config")
	}
	return filepath.Join(".kube", "config")
}

func (this kubeconfigOverwrites) resolveDefault() ([]byte, string, error) {
	fn := this.resolveDefaultFile()
	b, err := os.ReadFile(fn)
	return b, fn, err
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

func (this kubeconfigOverwrites) resolveServiceToken() (string, error) {
	v, err := this.dataFromFile("token", this.resolveServiceTokenFile())
	if err != nil {
		return "", err
	}
	return string(v), nil
}

func (this kubeconfigOverwrites) resolveServiceRootCaFile() string {
	if v := this.serviceRootCaFile; v != "" {
		return v
	}
	return ServiceRootCAFile
}

func (this kubeconfigOverwrites) resolveServiceRootCaData() ([]byte, error) {
	return this.dataFromFile("root CA", this.resolveServiceRootCaFile())
}

func (this kubeconfigOverwrites) resolveServiceNamespaceFile() string {
	if v := this.serviceNamespaceFile; v != "" {
		return v
	}
	return ServiceNamespaceFile
}

func (this kubeconfigOverwrites) resolveServiceNamespace() (string, error) {
	v, err := this.dataFromFile("namespace", this.resolveServiceNamespaceFile())
	if err != nil {
		return "", err
	}
	return string(v), err
}

func (this kubeconfigOverwrites) dataFromFile(name, fn string) ([]byte, error) {
	v, err := os.ReadFile(fn)
	if err != nil {
		return nil, errors.Config.Newf("can't read %s file %q: %w", name, fn, err)
	}
	return v, nil
}

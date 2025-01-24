package kubernetes

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"dario.cat/mergo"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	ServiceTokenFile     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	ServiceRootCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	ServiceNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	KubeconfigInCluster   = "incluster"
	EnvVarKubeconfig      = "KUBE_CONFIG"
	EnvVarKubeconfigFiles = "KUBECONFIG"
)

var (
	configGvk = schema.GroupVersionKind{Version: clientcmdlatest.Version, Kind: "Config"}
)

func NewKubeconfig(plain string) (Kubeconfig, error) {
	var buf Kubeconfig
	if err := buf.Set(plain); err != nil {
		return Kubeconfig{}, err
	}
	return buf, nil
}

func MustNewKubeconfig(plain string) Kubeconfig {
	buf, err := NewKubeconfig(plain)
	if err != nil {
		panic(err)
	}
	return buf
}

type Kubeconfig struct {
	plain      []byte
	overwrites kubeconfigOverwrites
}

func (this Kubeconfig) MarshalText() ([]byte, error) {
	if err := this.Validate(); err != nil {
		return nil, err
	}
	return this.plain, nil
}

func (this *Kubeconfig) UnmarshalText(text []byte) error {
	buf := Kubeconfig{plain: text, overwrites: this.overwrites}
	if err := buf.Validate(); err != nil {
		return err
	}

	*this = buf
	return nil
}

func (this Kubeconfig) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}
	return string(v)
}

func (this Kubeconfig) Validate() error {
	_, err := this.loadConfig()
	return err
}

func (this *Kubeconfig) Set(plain string) error {
	return this.UnmarshalText([]byte(plain))
}

func (this Kubeconfig) IsZero() bool {
	return len(this.plain) == 0
}

func (this Kubeconfig) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Kubeconfig:
		return this.isEqualTo(&v)
	case *Kubeconfig:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Kubeconfig) isEqualTo(other *Kubeconfig) bool {
	return bytes.Equal(this.plain, other.plain)
}

func (this *Kubeconfig) loadConfig() (*clientcmdapi.Config, error) {
	if len(this.plain) == 0 {
		return this.loadDefaultConfig()
	}

	return this.loadConfigFrom(this.plain)
}

func (this *Kubeconfig) loadConfigFrom(plain []byte) (*clientcmdapi.Config, error) {
	if string(plain) == KubeconfigInCluster {
		return this.loadInclusterConfig()
	}

	raw, err := os.ReadFile(string(plain))
	if err != nil {
		return nil, err
	}

	return this.parseConfigFrom(raw)
}

func (this *Kubeconfig) parseConfigFrom(raw []byte) (*clientcmdapi.Config, error) {
	decoded, _, err := clientcmdlatest.Codec.Decode(raw, &configGvk, clientcmdapi.NewConfig())
	if err != nil {
		return nil, err
	}
	return decoded.(*clientcmdapi.Config), nil
}

func (this *Kubeconfig) loadDefaultConfig() (*clientcmdapi.Config, error) {
	if v, ok := os.LookupEnv(EnvVarKubeconfig); ok && len(v) > 0 {
		// As path was empty, but KUBE_CONFIG is set, use it's content.
		result, err := this.parseConfigFrom([]byte(v))
		if err != nil {
			return nil, errors.Config.Newf("cannot parse kubeconfig of environment variable %s: %w", EnvVarKubeconfig, err)
		}
		return result, nil
	}

	if v, ok := os.LookupEnv(EnvVarKubeconfigFiles); ok && len(v) > 0 {
		result := clientcmdapi.NewConfig()
		for _, fn := range strings.Split(v, string([]rune{filepath.ListSeparator})) {
			cfg, err := clientcmd.LoadFromFile(fn)
			if err != nil {
				return nil, err
			}
			if err := mergo.Merge(result, cfg); err != nil {
				return nil, err
			}
		}
		return result, nil
	}

	v, fn, err := this.overwrites.resolveDefault()
	if sys.IsNotExist(err) {
		if result, err := this.loadInclusterConfig(); errors.Is(err, rest.ErrNotInCluster) {
			return nil, errors.Config.Newf("neither does the default kubeconfig %q exists nor was a specific file provided nor was the environment variable %s and %s provided nor does this instance run inside kubernetes directly", fn, EnvVarKubeconfig, EnvVarKubeconfigFiles)
		} else if err != nil {
			return nil, err
		} else {
			return result, nil
		}
	}
	if err != nil {
		return nil, errors.Config.Newf("cannot load kubeconfig %q: %w", fn, err)
	}

	result, err := this.parseConfigFrom(v)
	if err != nil {
		return nil, errors.Config.Newf("cannot parse kubeconfig %q: %w", fn, err)
	}
	return result, nil
}

func (this *Kubeconfig) loadInclusterConfig() (result *clientcmdapi.Config, err error) {
	cluster := clientcmdapi.NewCluster()
	if cluster.Server, err = this.overwrites.resolveServiceHost(); err != nil {
		return nil, err
	}
	if cluster.CertificateAuthorityData, err = this.overwrites.resolveServiceRootCaData(); err != nil {
		return nil, err
	}

	authInfo := clientcmdapi.NewAuthInfo()
	if authInfo.Token, err = this.overwrites.resolveServiceToken(); err != nil {
		return nil, err
	}

	context := clientcmdapi.NewContext()
	if context.Namespace, err = this.overwrites.resolveServiceNamespace(); err != nil {
		return nil, err
	}
	context.AuthInfo = KubeconfigInCluster
	context.Cluster = KubeconfigInCluster
	context.LocationOfOrigin = KubeconfigInCluster

	result = clientcmdapi.NewConfig()
	result.Clusters[KubeconfigInCluster] = cluster
	result.AuthInfos[KubeconfigInCluster] = authInfo
	result.Contexts[KubeconfigInCluster] = context
	result.CurrentContext = KubeconfigInCluster

	return result, nil
}

func (this *Kubeconfig) GetClient(contextName, namespace string) (Client, error) {
	return this.getClient(contextName, namespace)
}

func (this *Kubeconfig) getClient(contextName, namespace string) (*client, error) {
	loader := kubeconfigLoader{
		loader:  this.loadConfig,
		context: contextName,
	}

	loadedConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loader,
		&clientcmd.ConfigOverrides{
			CurrentContext: loader.context,
		},
	)

	rc, err := loadedConfig.RawConfig()
	if err != nil {
		return nil, err
	}
	if rc.CurrentContext == "" {
		return nil, clientcmd.ErrNoContext
	}

	if rc.Contexts == nil {
		return nil, errors.Config.Newf("no contexts defined in kubeconfig")
	} else if ctx, ok := rc.Contexts[rc.CurrentContext]; !ok {
		return nil, errors.Config.Newf("kubeconfig does not contain context %q", rc.CurrentContext)
	} else if namespace == "" {
		namespace = ctx.Namespace
	}

	restConfig, err := loadedConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	return &client{
		restConfig:  restConfig,
		contextName: rc.CurrentContext,
		namespace:   namespace,
	}, nil
}

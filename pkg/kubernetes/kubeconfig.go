package kubernetes

import (
	"fmt"
	"os"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/transport"
	certutil "k8s.io/client-go/util/cert"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/sys"
)

const (
	ServiceTokenFile     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	ServiceRootCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	ServiceNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

	KubeconfigInCluster = "incluster"
	KubeconfigMock      = "mock"
	EnvVarKubeconfig    = "KUBE_CONFIG"
	DefaultContext      = "default"
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
	plain      string
	overwrites kubeconfigOverwrites
}

func (this *Kubeconfig) MarshalText() ([]byte, error) {
	return []byte(this.plain), nil
}

func (this *Kubeconfig) UnmarshalText(text []byte) error {
	plain := string(text)
	switch plain {
	case "", KubeconfigInCluster, KubeconfigMock:
		*this = Kubeconfig{plain: plain, overwrites: this.overwrites}
		return nil
	default:
		fi, err := os.Stat(plain)
		if err != nil {
			return errors.Config.Newf("illegal kubeconfig %q: %w", plain, err)
		}
		if fi.IsDir() {
			return errors.Config.Newf("illegal kubeconfig %q: not a file", plain)
		}
		*this = Kubeconfig{plain: plain, overwrites: this.overwrites}
		return nil
	}
}

func (this *Kubeconfig) String() string {
	v, err := this.MarshalText()
	if err != nil {
		return fmt.Sprintf("ERR: %v", err)
	}
	return string(v)
}

func (this *Kubeconfig) Validate() error {
	return nil
}

func (this *Kubeconfig) Set(plain string) error {
	return this.UnmarshalText([]byte(plain))
}

func (this *Kubeconfig) IsZero() bool {
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
	return this.plain == other.plain
}

func (this *Kubeconfig) GetClient(contextName string) (Client, error) {
	return this.getClient(contextName)
}

func (this *Kubeconfig) getClient(contextName string) (*client, error) {
	switch this.plain {
	case "":
		return this.loadDefaultClient(contextName)
	case KubeconfigInCluster:
		return this.loadInclusterClient(contextName)
	case KubeconfigMock:
		return this.loadMockClient(contextName)
	default:
		return this.loadFromFileClient(this.plain, contextName)
	}
}

func (this *Kubeconfig) loadDefaultClient(contextName string) (*client, error) {
	if v, ok := os.LookupEnv(EnvVarKubeconfig); ok {
		// As path was empty, but KUBE_CONFIG is set, use it's content.
		return this.loadDirectClient(EnvVarKubeconfig, []byte(v), contextName)
	}

	if contextName == "" || contextName == DefaultContext {
		// Try in cluster...
		if result, err := this.loadInclusterClient(contextName); sys.IsNotExist(err) || errors.Is(err, rest.ErrNotInCluster) {
			// Ignore...
		} else if err != nil {
			return nil, err
		} else {
			return result, nil
		}
	}

	path := this.overwrites.resolveDefaultPath()
	result, err := this.loadFromFileClient(path, contextName)
	if sys.IsNotExist(err) {
		return nil, errors.Config.Newf("neither does the default kubeconfig %q exists nor was a specific file provided nor was the environment variable %s provided nor does this instance run inside kubernetes directly", path, EnvVarKubeconfig)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (this *Kubeconfig) loadInclusterClient(contextName string) (*client, error) {
	if contextName != "" && contextName != DefaultContext {
		return nil, errors.Config.Newf("kubeconfig of type %s does not support contexts; but got: %s", KubeconfigInCluster, contextName)
	}

	result := client{
		plainSource: KubeconfigInCluster,
		restConfig: &rest.Config{
			TLSClientConfig: rest.TLSClientConfig{},
		},
	}

	var err error

	if result.restConfig.Host, err = this.overwrites.resolveServiceHost(); err != nil {
		return nil, err
	}

	tokenFile := this.overwrites.resolveServiceTokenFile()
	ts := transport.NewCachedFileTokenSource(tokenFile)
	if _, err := ts.Token(); err != nil {
		return nil, err
	}
	result.restConfig.WrapTransport = transport.TokenSourceWrapTransport(ts)

	rootCaFile := this.overwrites.resolveServiceRootCaFile()
	if _, err := certutil.NewPool(rootCaFile); err != nil {
		return nil, errors.System.Newf("expected to load root CA config from %s, but got err: %v", rootCaFile, err)
	}
	result.restConfig.TLSClientConfig.CAFile = rootCaFile

	namespaceFile := this.overwrites.resolveServiceNamespaceFile()
	if nsb, err := os.ReadFile(namespaceFile); err != nil {
		return nil, errors.System.Newf("expected to load namespace from %s, but got err: %v", namespaceFile, err)
	} else {
		result.namespace = string(nsb)
	}

	return &result, nil
}

func (this *Kubeconfig) loadMockClient(contextName string) (*client, error) {
	if contextName == "" || contextName == DefaultContext {
		contextName = "mock"
	}
	return &client{
		plainSource: KubeconfigMock,
		contextName: contextName,
	}, nil
}

func (this *Kubeconfig) loadDirectClient(plainSource string, content []byte, contextName string) (*client, error) {
	return this.loadClientUsing(plainSource, &kubeconfigLoader{
		context: contextName,
		loader: func() (*clientcmdapi.Config, error) {
			return clientcmd.Load(content)
		},
	})
}

func (this *Kubeconfig) loadFromFileClient(file, contextName string) (*client, error) {
	return this.loadClientUsing(file, &kubeconfigLoader{
		context: contextName,
		loader: func() (*clientcmdapi.Config, error) {
			return clientcmd.LoadFromFile(file)
		},
	})
}

func (this *Kubeconfig) loadClientUsing(plainSource string, loader *kubeconfigLoader) (*client, error) {
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
	restConfig, err := loadedConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	return &client{
		plainSource: plainSource,
		restConfig:  restConfig,
		contextName: rc.CurrentContext,
	}, nil
}

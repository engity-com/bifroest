package kubernetes

import (
	"dario.cat/mergo"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

type kubeconfigLoader struct {
	clientcmd.ClientConfigLoader
	loader  func() (*clientcmdapi.Config, error)
	context string
}

func (this kubeconfigLoader) Load() (*clientcmdapi.Config, error) {
	result := clientcmdapi.NewConfig()
	result.CurrentContext = this.context

	loaded, err := this.loader()
	if err != nil {
		return nil, err
	}
	if err := mergo.Merge(result, loaded); err != nil {
		return nil, err
	}

	return result, nil
}

func (this kubeconfigLoader) IsDefaultConfig(*restclient.Config) bool {
	return false
}

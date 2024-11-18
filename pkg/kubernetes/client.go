package kubernetes

import (
	"context"
	gonet "net"
	"reflect"
	"sync/atomic"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/engity-com/bifroest/pkg/errors"
)

type Client interface {
	RestConfig() *rest.Config
	ClientSet() (kubernetes.Interface, error)
	DialPod(ctx context.Context, namespace, name, port string) (gonet.Conn, error)

	ContextName() string
	Namespace() string
}

type client struct {
	restConfig  *rest.Config
	plainSource string
	contextName string
	namespace   string

	typed atomic.Pointer[kubernetes.Clientset]
}

func (this *client) String() string {
	return this.plainSource
}

func (this *client) RestConfig() *rest.Config {
	return this.restConfig
}

func (this *client) ClientSet() (kubernetes.Interface, error) {
	for {
		result := this.typed.Load()
		if result != nil {
			return result, nil
		}

		if this.restConfig == nil {
			return nil, errors.System.Newf("currently there is no support for mock of %v", reflect.TypeOf((*kubernetes.Interface)(nil)).Elem())
		}

		result, err := kubernetes.NewForConfig(this.restConfig)
		if err != nil {
			return nil, errors.System.Newf("cannot create new typed kubernetes client from %q: %w", this.plainSource, err)
		}
		if this.typed.CompareAndSwap(nil, result) {
			return result, nil
		}
	}
}

func (this *client) ContextName() string {
	return this.contextName
}

func (this *client) Namespace() string {
	return this.namespace
}

package environment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/errdefs"
	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/level"
	glssh "github.com/gliderlabs/ssh"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	watch2 "k8s.io/apimachinery/pkg/watch"
	corev1 "k8s.io/client-go/applyconfigurations/core/v1"
	v2 "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	bkp "github.com/engity-com/bifroest/pkg/kubernetes"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	_ = RegisterRepository(NewKubernetesRepository)
)

const (
	KubernetesLabelPrefix    = "org.engity.bifroest/"
	KubernetesLabelFlow      = KubernetesLabelPrefix + "flow"
	KubernetesLabelSessionId = KubernetesLabelPrefix + "session-id"

	KubernetesAnnotationPrefix                = KubernetesLabelPrefix
	KubernetesAnnotationCreatedRemoteUser     = KubernetesAnnotationPrefix + "created-remote-user"
	KubernetesAnnotationCreatedRemoteHost     = KubernetesAnnotationPrefix + "created-remote-host"
	KubernetesAnnotationShellCommand          = KubernetesAnnotationPrefix + "shellCommand"
	KubernetesAnnotationExecCommand           = KubernetesAnnotationPrefix + "execCommand"
	KubernetesAnnotationSftpCommand           = KubernetesAnnotationPrefix + "sftpCommand"
	KubernetesAnnotationUser                  = KubernetesAnnotationPrefix + "user"
	KubernetesAnnotationGroup                 = KubernetesAnnotationPrefix + "group"
	KubernetesAnnotationDirectory             = KubernetesAnnotationPrefix + "directory"
	KubernetesAnnotationPortForwardingAllowed = KubernetesAnnotationPrefix + "portForwardingAllowed"

	amountOfEnsureTries = 5
)

type KubernetesRepository struct {
	flow         configuration.FlowName
	conf         *configuration.EnvironmentKubernetes
	alternatives alternatives.Provider
	imp          imp.Imp

	client bkp.Client

	Logger              log.Logger
	defaultLogLevelName string

	sessionIdMutex  common.KeyedMutex[session.Id]
	activeInstances sync.Map
}

func NewKubernetesRepository(_ context.Context, flow configuration.FlowName, conf *configuration.EnvironmentKubernetes, ap alternatives.Provider, i imp.Imp) (*KubernetesRepository, error) {
	fail := func(err error) (*KubernetesRepository, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*KubernetesRepository, error) {
		return fail(fmt.Errorf(msg, args...))
	}

	if conf == nil {
		return failf("nil configuration")
	}

	core := struct{}{}
	kCfg, err := conf.Config.Render(&core)
	if err != nil {
		return fail(err)
	}

	kCtx, err := conf.Context.Render(&core)
	if err != nil {
		return fail(err)
	}

	client, err := kCfg.GetClient(kCtx)
	if err != nil {
		return fail(err)
	}

	result := KubernetesRepository{
		flow:         flow,
		conf:         conf,
		alternatives: ap,
		imp:          i,
		client:       client,
	}

	lp := result.logger().GetProvider()
	if la, ok := lp.(level.Aware); ok {
		if lna, ok := lp.(level.NamesAware); ok {
			lvl := la.GetLevel()
			if result.defaultLogLevelName, err = lna.GetLevelNames().ToName(lvl); err != nil {
				return failf("cannot transform to name of level %v: %w", lvl, err)
			}
		}
	}

	return &result, nil
}

func (this *KubernetesRepository) WillBeAccepted(ctx Context) (ok bool, err error) {
	fail := func(err error) (bool, error) {
		return false, err
	}

	if ok, err = this.conf.LoginAllowed.Render(ctx); err != nil {
		return fail(fmt.Errorf("cannot evaluate if user is allowed to login or not: %w", err))
	}

	return ok, nil
}

func (this *KubernetesRepository) DoesSupportPty(Context, glssh.Pty) (bool, error) {
	return true, nil
}

func (this *KubernetesRepository) Ensure(req Request) (result Environment, err error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (Environment, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	if ok, err := this.WillBeAccepted(req); err != nil {
		return fail(err)
	} else if !ok {
		return fail(ErrNotAcceptable)
	}

	sess := req.Authorization().FindSession()
	if sess == nil {
		return failf(errors.System, "authorization without session")
	}

	try := 1
	for {
		result, err = this.findOrEnsureBySession(req.Context(), sess, nil, req)
		if (errors.Is(err, podContainsProblemsErr) || errors.Is(err, bkp.ErrEndpointNotFound) || errors.Is(err, bkp.ErrPodNotFound)) &&
			try <= amountOfEnsureTries && req.Context().Done() == nil {
			try++
			continue
		}
		if err != nil {
			return fail(err)
		}
		return result, nil
	}
}

func (this *KubernetesRepository) createPodBy(req Request, sess session.Session) (*v1.Pod, error) {
	var pp PreparationProgress
	fail := func(err error) (*v1.Pod, error) {
		if pp != nil {
			_ = pp.Error(err)
		}
		return nil, err
	}
	failf := func(t errors.Type, msg string, args ...any) (*v1.Pod, error) {
		return fail(errors.Newf(t, msg, args...))
	}

	success := false

	config, managedSecretName, err := this.resolvePodConfig(req, sess)
	if err != nil {
		return fail(err)
	}
	if managedSecretName != "" {
		defer func() {
			if !success {
				if err := this.deletePullSecret(req.Context(), managedSecretName, config); err != nil {
					req.Connection().Logger().WithError(err).
						With("namespace", config.Namespace).
						With("name", managedSecretName).
						Warn("cannot delete orphan pull secret; it might stay and needs to be removed manually")
				}
			}
		}()
	}

	clientSet, err := this.client.ClientSet()
	if err != nil {
		return fail(err)
	}

	client := clientSet.CoreV1().Pods(config.Namespace)

	if pp, err = req.StartPreparation("create-pod", "Create POD", PreparationProgressAttributes{
		"namespace": config.Namespace,
		"name":      config.Name,
		"image":     config.Spec.Containers[0].Image,
	}); err != nil {
		return fail(err)
	}

	created, err := client.Create(req.Context(), config, metav1.CreateOptions{
		FieldValidation: "Strict",
	})
	if err != nil {
		return failf(errors.System, "cannot create POD: %w", err)
	}
	defer func() {
		if !success {
			if err := this.deletePod(req.Context(), config); err != nil {
				req.Connection().Logger().WithError(err).
					With("namespace", config.Namespace).
					With("name", config.Name).
					Warn("cannot delete orphan pod; it might stay and needs to be removed manually")
			}
		}
	}()
	created.TypeMeta = config.TypeMeta

	if managedSecretName != "" {
		if err := this.addOwnerReferenceToPullSecret(req.Context(), managedSecretName, created); err != nil {
			return fail(err)
		}
	}

	watch, err := client.Watch(req.Context(), metav1.ListOptions{
		FieldSelector: "metadata.name=" + created.Name,
	})
	if err != nil {
		return failf(errors.System, "cannot watch POD %v/%v: %w", created.Namespace, created.Namespace, err)
	}
	defer watch.Stop()

	var readyTimeout time.Duration
	if readyTimeout, err = this.conf.ReadyTimeout.Render(req); err != nil {
		return fail(err)
	}

	readyTimer := time.NewTimer(readyTimeout)
	defer readyTimer.Stop()
	for {
		select {
		case <-readyTimer.C:
			return fail(errors.System.Newf("pod %v/%v was still not ready after %v", created.Namespace, created.Name, readyTimeout))
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case event := <-watch.ResultChan():
			if p, ok := event.Object.(*v1.Pod); ok {
				switch p.Status.Phase {
				case v1.PodPending:
					// We know this is not accurate, but somehow a kind or progress is better than nothing...
					if pp != nil {
						if err := pp.Report(0.3); err != nil {
							return nil, err
						}
					}
				case v1.PodRunning:
					if pp != nil {
						if err := pp.Done(); err != nil {
							return nil, err
						}
					}
					success = true
					return p, nil
				default:
					return fail(errors.System.Newf("pod %v/%v is unexpted state, see kubernetes logs for more details", p.Namespace, p.Name))
				}
			}
		}
	}
}

func (this *KubernetesRepository) ensureNamespace(ctx context.Context, namespace string) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot ensure namespace %q: %w", namespace, err)
	}

	clientSet, err := this.client.ClientSet()
	if err != nil {
		return fail(err)
	}
	client := clientSet.CoreV1().Namespaces()

	_, err = client.Get(ctx, namespace, metav1.GetOptions{})
	if kerrors.IsNotFound(err) {
		// Ok... not there, create it...
		req := v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		}
		_, err = client.Create(ctx, &req, metav1.CreateOptions{
			FieldValidation: "Strict",
		})
	}
	if err != nil {
		return fail(err)
	}

	return nil
}

func (this *KubernetesRepository) resolvePullSecretName(req Request, forImage string, pod *v1.Pod) (name string, managed bool, err error) {
	fail := func(t errors.Type, err error) (string, bool, error) {
		return "", false, t.Newf("cannot resolve image pull secret name: %w", err)
	}
	failf := func(t errors.Type, msg string, args ...any) (string, bool, error) {
		return fail(t, t.Newf(msg, args...))
	}

	name, err = this.conf.ImagePullSecretName.Render(req)
	if err != nil {
		return fail(errors.Config, err)
	}

	credentials, err := this.resolvePullCredentials(req, forImage)
	if err != nil {
		return fail(errors.Config, err)
	}

	if len(credentials) == 0 {
		// Either if set or empty
		return name, false, nil
	}

	if name == "" {
		name = "pull-secret." + pod.Name
	}

	// Now ensure that the secret exists...
	clientSet, err := this.client.ClientSet()
	if err != nil {
		return fail(errors.System, err)
	}
	client := clientSet.CoreV1().Secrets(pod.Namespace)

	template := corev1.Secret(name, pod.Namespace)
	template.Type = common.P(v1.SecretTypeDockerConfigJson)
	template.Data = map[string][]byte{
		v1.DockerConfigJsonKey: credentials,
	}
	template.Labels = pod.Labels

	if _, err := client.Apply(req.Context(), template, metav1.ApplyOptions{Force: true, FieldManager: "application/apply-patch"}); err != nil {
		return failf(errors.System, "cannot apply image secret %v/%v for to be crated pod %v/%v: %w", pod.Namespace, name, pod.Namespace, pod.Name, err)
	}

	return name, true, nil
}

func (this *KubernetesRepository) deletePullSecret(ctx context.Context, name string, pod *v1.Pod) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot remove image pull secret %v/%v: %w", pod.Namespace, name, err)
	}

	clientSet, err := this.client.ClientSet()
	if err != nil {
		return fail(err)
	}
	client := clientSet.CoreV1().Secrets(pod.Namespace)

	if err := client.Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: common.P(metav1.DeletePropagationForeground)}); kerrors.IsNotFound(err) {
		// Ignore
	} else if err != nil {
		return fail(err)
	}

	return nil
}
func (this *KubernetesRepository) deletePod(ctx context.Context, pod *v1.Pod) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot remove pod %v/%v: %w", pod.Namespace, pod.Name, err)
	}

	clientSet, err := this.client.ClientSet()
	if err != nil {
		return fail(err)
	}
	client := clientSet.CoreV1().Pods(pod.Namespace)

	if err := client.Delete(ctx, pod.Name, metav1.DeleteOptions{PropagationPolicy: common.P(metav1.DeletePropagationForeground)}); kerrors.IsNotFound(err) {
		// Ignore
	} else if err != nil {
		return fail(err)
	}

	return nil
}

func (this *KubernetesRepository) addOwnerReferenceToPullSecret(ctx context.Context, name string, pod *v1.Pod) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot add owner reference for image pull secret %q: %w", name, err)
	}

	clientSet, err := this.client.ClientSet()
	if err != nil {
		return fail(err)
	}
	client := clientSet.CoreV1().Secrets(pod.Namespace)

	patch := map[string]any{
		"metadata": map[string]any{
			"ownerReferences": []any{
				map[string]any{
					"apiVersion": pod.APIVersion,
					"kind":       pod.Kind,
					"name":       pod.Name,
					"uid":        pod.UID,
				},
			},
		},
	}

	patchB, err := json.Marshal(patch)
	if err != nil {
		return fail(err)
	}

	if _, err := client.Patch(ctx, name, types.StrategicMergePatchType, patchB, metav1.PatchOptions{}); err != nil {
		return fail(err)
	}

	return nil
}

func (this *KubernetesRepository) resolvePullCredentials(req Request, image string) ([]byte, error) {
	fail := func(err error) ([]byte, error) {
		return nil, errors.Config.Newf("cannot resolve image pull credentials: %w", err)
	}

	plain, err := this.conf.ImagePullCredentials.Render(req)
	if err != nil {
		return fail(err)
	}

	if plain == "" {
		return nil, nil
	}

	var buf dockerPullSecret
	if err := json.Unmarshal([]byte(plain), &buf); err == nil && len(buf.Auths) > 0 {
		// We can take it as it is, because it is fully valid...
		return []byte(plain), nil
	}

	ir := this.extractRegistryFromImage(image)

	if v, err := registry.DecodeAuthConfig(plain); err == nil && (v.Auth != "" || v.Username != "" || v.Password != "") {
		// Seems to be an encoded docker authConfig. Just wrap it...
		buf.Auths = map[string]registry.AuthConfig{
			ir: *v,
		}
	}

	if len(buf.Auths) == 0 {
		var v registry.AuthConfig
		if err := json.Unmarshal([]byte(plain), &v); err == nil && (v.Auth != "" || v.Username != "" || v.Password != "") {
			// Seems to be a json encoded authConfig. Just wrap it...
			buf.Auths = map[string]registry.AuthConfig{
				ir: v,
			}
		}
	}

	if len(buf.Auths) == 0 {
		// Seems to be direct auth string...
		buf.Auths = map[string]registry.AuthConfig{
			ir: {
				Auth: plain,
			},
		}
	}

	result, err := json.Marshal(buf)
	if err != nil {
		return fail(err)
	}

	return result, nil
}

func (this *KubernetesRepository) extractRegistryFromImage(image string) string {
	pathAndTag := strings.SplitAfterN(image, ":", 2)
	path := pathAndTag[0]

	slashed := strings.SplitAfterN(path, "/", 2)
	if len(slashed) < 2 {
		// Like "image"
		return "index.docker.io"
	}

	if strings.IndexByte(slashed[0], '.') < 0 {
		// Like "project/image[/..]"
		return "index.docker.io"
	}

	return slashed[0]
}

type dockerPullSecret struct {
	Auths map[string]registry.AuthConfig `json:"auths"`
}

func (this *KubernetesRepository) resolvePodConfig(req Request, sess session.Session) (result *v1.Pod, managedSecretName string, err error) {
	fail := func(err error) (*v1.Pod, string, error) {
		return nil, "", err
	}
	failf := func(msg string, args ...any) (*v1.Pod, string, error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	result = &v1.Pod{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Pod",
		},
	}

	if result.Name, err = this.conf.Name.Render(req); err != nil {
		return fail(err)
	}
	if result.Namespace, err = this.conf.Namespace.Render(req); err != nil {
		return fail(err)
	}
	if result.Namespace == "" {
		result.Namespace = this.client.Namespace()
	}

	if err := this.ensureNamespace(req.Context(), result.Namespace); err != nil {
		return failf("cannot ensure POD's namespace (%q): %w", result.Namespace, err)
	}

	remote := req.Connection().Remote()
	result.Labels = map[string]string{
		KubernetesLabelFlow:      this.flow.String(),
		KubernetesLabelSessionId: sess.Id().String(),
	}

	result.Annotations = map[string]string{
		KubernetesAnnotationCreatedRemoteUser: remote.User(),
		KubernetesAnnotationCreatedRemoteHost: remote.Host().String(),
	}
	if result.Annotations[KubernetesAnnotationShellCommand], err = this.resolveEncodedShellCommand(req); err != nil {
		return fail(err)
	}
	if result.Annotations[KubernetesAnnotationExecCommand], err = this.resolveEncodedExecCommand(req); err != nil {
		return fail(err)
	}
	if result.Annotations[KubernetesAnnotationSftpCommand], err = this.resolveEncodedSftpCommand(req); err != nil {
		return fail(err)
	}
	if result.Annotations[KubernetesAnnotationUser], err = this.conf.User.Render(req); err != nil {
		return failf("cannot evaluate user: %w", err)
	}
	if result.Annotations[KubernetesAnnotationGroup], err = this.conf.Group.Render(req); err != nil {
		return failf("cannot evaluate group: %w", err)
	}
	if result.Annotations[KubernetesAnnotationDirectory], err = this.conf.Directory.Render(req); err != nil {
		return failf("cannot evaluate directory: %w", err)
	}
	if v, err := this.conf.PortForwardingAllowed.Render(req); err != nil {
		return failf("cannot evaluate portForwardingAllowed: %w", err)
	} else if v {
		result.Annotations[KubernetesAnnotationPortForwardingAllowed] = "true"
	}

	var containerImage string
	if v, err := this.resolveContainerConfig(req, sess); err != nil {
		return fail(err)
	} else {
		result.Spec.Containers = []v1.Container{v}
		containerImage = v.Image
	}

	if v, err := this.resolveInitContainerConfig(req, sess); err != nil {
		return fail(err)
	} else {
		result.Spec.InitContainers = []v1.Container{v}
	}

	result.Spec.OS = &v1.PodOS{}
	switch this.conf.Os {
	case sys.OsLinux:
		result.Spec.OS = &v1.PodOS{Name: v1.Linux}
	case sys.OsWindows:
		result.Spec.OS = &v1.PodOS{Name: v1.Windows}
	default:
		return failf("os %v is unsupported for kubernetes environments", this.conf.Os)
	}

	secretName, secretManaged, err := this.resolvePullSecretName(req, containerImage, result)
	if err != nil {
		return fail(err)
	}
	if secretName != "" {
		result.Spec.ImagePullSecrets = []v1.LocalObjectReference{{
			Name: secretName,
		}}
	}

	if result.Spec.ServiceAccountName, err = this.conf.ServiceAccountName.Render(req); err != nil {
		return fail(err)
	}
	result.Spec.RestartPolicy = v1.RestartPolicyNever
	result.Spec.NodeSelector = map[string]string{
		v1.LabelOSStable:   this.conf.Os.String(),
		v1.LabelArchStable: this.conf.Arch.Oci(),
	}
	// TODO! Maybe, allow additional node selectors?

	result.Spec.Volumes = []v1.Volume{{
		Name: "imp",
		VolumeSource: v1.VolumeSource{
			EmptyDir: &v1.EmptyDirVolumeSource{},
		},
	}}
	// TODO! Maybe, allow other volumens?

	result.Spec.DNSConfig = &v1.PodDNSConfig{}
	if result.Spec.DNSConfig.Nameservers, err = this.conf.DnsServers.Render(req); err != nil {
		return failf("cannot evaluate dnsServer: %w", err)
	}
	if result.Spec.DNSConfig.Searches, err = this.conf.DnsSearch.Render(req); err != nil {
		return failf("cannot evaluate dnsSearch: %w", err)
	}

	if secretManaged {
		return result, secretName, nil
	}

	return result, "", nil
}

func (this *KubernetesRepository) resolveInitContainerConfig(req Request, _ session.Session) (result v1.Container, err error) {
	fail := func(err error) (v1.Container, error) {
		return v1.Container{}, err
	}
	failf := func(msg string, args ...any) (v1.Container, error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	result.Name = "init"

	var wg sync.WaitGroup
	doneCh := make(chan struct{}, 1)
	defer close(doneCh)
	var ppErr atomic.Pointer[error]
	var findErr atomic.Pointer[error]

	wg.Add(1)
	go func() {
		defer wg.Done()

		var pp PreparationProgress

		oneSecondPassedTimer := time.NewTimer(1 * time.Second)
		defer oneSecondPassedTimer.Stop()

		for {
			select {
			case <-oneSecondPassedTimer.C:
				if pp, err = req.StartPreparation("ensure-image", "Ensure IMP image", PreparationProgressAttributes{
					"os":   this.conf.Os,
					"arch": this.conf.Arch,
				}); err != nil {
					ppErr.Store(&err)
					return
				}

			case _, _ = <-doneCh:
				if pp != nil {
					var pErr error
					if fErr := findErr.Load(); fErr != nil {
						pErr = pp.Error(*fErr)
					} else {
						pErr = pp.Done()
					}
					if pErr != nil {
						ppErr.Store(&pErr)
					}
				}
				return
			}
		}
	}()

	if result.Image, err = this.alternatives.FindOciImageFor(req.Context(), this.conf.Os, this.conf.Arch); err != nil {
		findErr.Store(&err)
		return fail(err)
	}

	doneCh <- struct{}{}
	wg.Wait()
	if err := ppErr.Load(); err != nil {
		return fail(*err)
	}

	var targetPath string

	switch this.conf.Os {
	case sys.OsLinux:
		targetPath = imp.DefaultInitPathUnix
	case sys.OsWindows:
		targetPath = imp.DefaultInitPathWindows
	default:
		return failf("os %v is unsupported for kubernetes environments", this.conf.Os)
	}

	result.VolumeMounts = []v1.VolumeMount{{
		Name:      "imp",
		MountPath: targetPath,
	}}

	result.Args = strslice.StrSlice{
		"imp-init",
		"--targetPath=" + targetPath,
		"--log.colorMode=always",
	}
	if this.defaultLogLevelName != "" {
		result.Args = append(result.Args, `--log.level=`+this.defaultLogLevelName)
	}

	return result, nil
}

func (this *KubernetesRepository) resolveContainerConfig(req Request, sess session.Session) (result v1.Container, err error) {
	fail := func(err error) (v1.Container, error) {
		return v1.Container{}, err
	}
	failf := func(msg string, args ...any) (v1.Container, error) {
		return fail(errors.Config.Newf(msg, args...))
	}

	result.Name = "bifroest"

	if result.Image, err = this.conf.Image.Render(req); err != nil {
		return fail(err)
	}

	switch this.conf.ImagePullPolicy {
	case configuration.PullPolicyIfAbsent:
		result.ImagePullPolicy = v1.PullIfNotPresent
	case configuration.PullPolicyAlways:
		result.ImagePullPolicy = v1.PullAlways
	case configuration.PullPolicyNever:
		result.ImagePullPolicy = v1.PullNever
	default:
		return failf("image pull policy %v is not supported for kubernetes environments", this.conf.ImagePullPolicy)
	}

	result.Ports = []v1.ContainerPort{{
		Name:          "imp",
		ContainerPort: 8683,
		Protocol:      "TCP",
	}}
	// TODO! Maybe, allow other ports?

	result.Command = strslice.StrSlice{}
	result.SecurityContext = &v1.SecurityContext{}
	result.Command = []string{sys.BifroestBinaryFileLocation(this.conf.Os)}
	if len(result.Command[0]) == 0 {
		return failf("cannot resolve target path for host %v", this.conf.Os)
	}
	if this.conf.Os == sys.OsLinux {
		result.SecurityContext.RunAsUser = common.P[int64](0)
		result.SecurityContext.RunAsGroup = common.P[int64](0)
	}

	result.Args = []string{
		`imp`,
		`--log.colorMode=always`,
	}
	if this.defaultLogLevelName != "" {
		result.Args = append(result.Args, `--log.level=`+this.defaultLogLevelName)
	}

	masterPub, err := this.imp.GetMasterPublicKey()
	if err != nil {
		return fail(err)
	}

	result.Env = []v1.EnvVar{{
		Name:  imp.EnvVarMasterPublicKey,
		Value: base64.RawStdEncoding.EncodeToString(masterPub.Marshal()),
	}, {
		Name:  session.EnvName,
		Value: sess.Id().String(),
	}}

	result.VolumeMounts = []v1.VolumeMount{{
		Name:      "imp",
		MountPath: result.Command[0],
		SubPath:   this.conf.Os.AppendExtToFilename("bifroest"),
		ReadOnly:  true,
	}}
	// TODO! Maybe, allow other volume mounts? (see above at POD config itself)

	result.LivenessProbe = &v1.Probe{
		ProbeHandler: v1.ProbeHandler{
			TCPSocket: &v1.TCPSocketAction{
				Port: intstr.FromInt32(imp.ServicePort),
			},
		},
		PeriodSeconds:    5,
		FailureThreshold: 1,
	}

	result.StartupProbe = &v1.Probe{
		ProbeHandler: v1.ProbeHandler{
			TCPSocket: &v1.TCPSocketAction{
				Port: intstr.FromInt32(imp.ServicePort),
			},
		},
		PeriodSeconds:    1,
		FailureThreshold: 60,
	}

	if vs, err := this.conf.Capabilities.Render(req); err != nil {
		return failf("cannot evaluate capabilities: %w", err)
	} else {
		result.SecurityContext.Capabilities = &v1.Capabilities{Add: *(*[]v1.Capability)(unsafe.Pointer(&vs))}
	}
	if v, err := this.conf.Privileged.Render(req); err != nil {
		return failf("cannot evaluate capabilities: %w", err)
	} else {
		result.SecurityContext.Privileged = common.P(v)
	}

	return result, nil
}

func (this *KubernetesRepository) resolveEncodedShellCommand(req Request) (string, error) {
	failf := func(msg string, args ...any) (string, error) {
		return "", errors.Config.Newf(msg, args...)
	}

	v, err := this.conf.ShellCommand.Render(req)
	if err != nil {
		return failf("cannot evaluate shellCommand: %w", err)
	}
	if len(v) == 0 {
		switch this.conf.Os {
		case sys.OsWindows:
			v = []string{`C:\WINDOWS\system32\cmd.exe`}
		case sys.OsLinux:
			v = []string{`/bin/sh`}
		default:
			return failf("shellCommand was not defined for kubernetes environment and default cannot be resolved for %v", this.conf.Os)
		}
	} else if len(v[0]) == 0 {
		return failf("first argument of shellCommand is empty")
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func (this *KubernetesRepository) resolveEncodedExecCommand(req Request) (string, error) {
	failf := func(msg string, args ...any) (string, error) {
		return "", errors.Config.Newf(msg, args...)
	}

	v, err := this.conf.ExecCommand.Render(req)
	if err != nil {
		return failf("cannot evaluate execCommand: %w", err)
	}
	if len(v) == 0 {
		switch this.conf.Os {
		case sys.OsWindows:
			v = []string{`C:\WINDOWS\system32\cmd.exe`, `/C`}
		case sys.OsLinux:
			v = []string{`/bin/sh`, `-c`}
		default:
			return failf("execCommand was not defined for kubernetes environment and default cannot be resolved for %v", this.conf.Os)
		}
	} else if len(v[0]) == 0 {
		return failf("first argument of execCommand is empty")
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func (this *KubernetesRepository) resolveEncodedSftpCommand(req Request) (string, error) {
	failf := func(msg string, args ...any) (string, error) {
		return "", errors.Config.Newf(msg, args...)
	}

	v, err := this.conf.SftpCommand.Render(req)
	if err != nil {
		return failf("cannot evaluate sftpCommand: %w", err)
	}
	if len(v) == 0 {
		v = []string{sys.BifroestBinaryFileLocation(this.conf.Os), `sftp-server`}
		if len(v[0]) == 0 {
			return failf("sftpCommand was not defined for kubernetes environment and default cannot be resolved for %v", this.conf.Os)
		}
	} else if len(v[0]) == 0 {
		return failf("first argument of sftpCommand is empty")
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func (this *KubernetesRepository) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	return this.findOrEnsureBySession(ctx, sess, opts, nil)
}

func (this *KubernetesRepository) findOrEnsureBySession(ctx context.Context, sess session.Session, opts *FindOpts, createUsing Request) (Environment, error) {
	fail := func(err error) (Environment, error) {
		return nil, err
	}

	sessId := sess.Id()
	rUnlocker := this.sessionIdMutex.RLock(sessId)
	rUnlock := func() {
		if rUnlocker != nil {
			rUnlocker()
		}
		rUnlocker = nil
	}
	defer rUnlock()

	ip, ok := this.activeInstances.Load(sessId)
	if ok {
		instance := ip.(*kubernetes)
		instance.owners.Add(1)
		return instance, nil
	}

	existing, err := this.findPodBySession(ctx, sess)
	if err != nil {
		return nil, err
	}
	if existing == nil && createUsing == nil {
		return fail(ErrNoSuchEnvironment)
	}
	rUnlock()

	defer this.sessionIdMutex.Lock(sessId)()

	ip, ok = this.activeInstances.Load(sessId)
	if ok {
		instance := ip.(*kubernetes)
		instance.owners.Add(1)
		return instance, nil
	}

	if existing != nil && existing.Status.Phase != v1.PodPending && existing.Status.Phase != v1.PodRunning {
		if opts.IsAutoCleanUpAllowed() || createUsing != nil {
			if _, err := this.removePod(ctx, existing.Namespace, existing.Name, createUsing); err != nil {
				return fail(err)
			}
		}
		if createUsing == nil {
			return fail(ErrNoSuchEnvironment)
		}
		existing = nil
	}

	if existing == nil {
		existing, err = this.createPodBy(createUsing, sess)
		if err != nil {
			return fail(err)
		}
	}

	logger := this.logger().
		With("namespace", existing.Namespace).
		With("name", existing.Name).
		With("sessionId", sessId)

	removePodUnchecked := func() {
		if _, err := this.removePod(ctx, existing.Namespace, existing.Name, nil); err != nil {
			logger.
				WithError(err).
				Warnf("cannot broken pod; need to be done manually")
		}
	}

	instance, err := this.new(ctx, existing, logger)
	if err != nil {
		if errors.Is(err, podContainsProblemsErr) || errors.Is(err, bkp.ErrEndpointNotFound) || errors.Is(err, bkp.ErrPodNotFound) {
			if createUsing != nil {
				removePodUnchecked()
				return fail(err)
			} else if opts.IsAutoCleanUpAllowed() {
				removePodUnchecked()
				return fail(ErrNoSuchEnvironment)
			}
		}
		return fail(err)
	}

	this.activeInstances.Store(sessId, instance)

	return instance, nil
}

func (this *KubernetesRepository) removePod(ctx context.Context, namespace, name string, ppe PreparationProgressEnabled) (_ bool, rErr error) {
	fail := func(err error) (bool, error) {
		return false, errors.System.Newf("cannot remove pod %v/%v: %w", namespace, name, err)
	}

	if ppe != nil {
		if pp, err := ppe.StartPreparation("remove-pod", "Remove existing POD", PreparationProgressAttributes{
			"namespace": namespace,
			"name":      name,
		}); err != nil {
			return fail(err)
		} else if pp != nil {
			defer func(pp PreparationProgress) {
				if rErr != nil {
					_ = pp.Error(rErr)
				} else {
					rErr = pp.Done()
				}
			}(pp)
		}
	}

	clientSet, err := this.client.ClientSet()
	if err != nil {
		return fail(err)
	}
	client := clientSet.CoreV1().Pods(namespace)

	if _, err := client.Get(ctx, name, metav1.GetOptions{}); errdefs.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return fail(err)
	}

	if err := client.Delete(ctx, name, metav1.DeleteOptions{}); errdefs.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return fail(err)
	}

	watch, err := client.Watch(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + name,
	})
	if errdefs.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return fail(err)
	}
	defer watch.Stop()

	l := this.logger().
		With("namespace", namespace).
		With("name", name)

	readyTimer := time.NewTimer(this.conf.RemoveTimeout)
	defer readyTimer.Stop()
	for {
		select {
		case <-readyTimer.C:
			if _, err := client.Get(ctx, name, metav1.GetOptions{}); errdefs.IsNotFound(err) {
				return false, nil
			}

			return fail(errors.System.Newf("pod %v/%v was still not removed after %v", namespace, name, this.conf.RemoveTimeout))
		case <-ctx.Done():
			return false, ctx.Err()
		case event := <-watch.ResultChan():
			l.With("event", event).Trace("event received while waiting for pod to be deleted...")
			switch event.Type {
			case watch2.Deleted:
				return true, nil
			case watch2.Modified, watch2.Added:
				// Yeah... ignore this for a moment...
			default:
				return fail(errors.System.Newf("pod %v/%v is unexpted state, see kubernetes logs for more details", namespace, name))
			}
		}
	}
}

func (this *KubernetesRepository) findPodBySession(ctx context.Context, sess session.Session) (*v1.Pod, error) {
	fail := func(err error) (*v1.Pod, error) {
		return nil, errors.System.Newf("cannot find pod by session %v: %w", sess, err)
	}

	client, err := this.podsClient()
	if err != nil {
		return fail(err)
	}

	candidates, err := client.List(ctx, metav1.ListOptions{
		LabelSelector: KubernetesLabelSessionId + "=" + sess.Id().String(),
		Limit:         1,
	})
	if err != nil {
		return fail(err)
	}
	if len(candidates.Items) == 0 {
		return nil, nil
	}

	return &candidates.Items[0], nil
}

func (this *KubernetesRepository) podsClient() (v2.PodInterface, error) {
	clientSet, err := this.client.ClientSet()
	if err != nil {
		return nil, err
	}

	if v := this.conf.Namespace; v.IsHardCoded() {
		if !v.IsZero() {
			return clientSet.CoreV1().Pods(v.String()), nil
		}
		if cv := this.client.Namespace(); cv != "" {
			return clientSet.CoreV1().Pods(cv), nil
		}
	}

	// All namespaces fallback
	return clientSet.CoreV1().Pods(""), nil
}

func (this *KubernetesRepository) Close() error {
	return nil
}

func (this *KubernetesRepository) Cleanup(ctx context.Context, opts *CleanupOpts) error {
	fail := func(err error) error {
		return errors.System.Newf("cannot cleanup potential orhpan kubernetes containers: %w", err)
	}

	l := opts.GetLogger(this.logger)

	client, err := this.podsClient()
	if err != nil {
		return fail(err)
	}

	listOpts := metav1.ListOptions{
		LabelSelector: KubernetesLabelFlow,
	}
	for {
		list, err := client.List(ctx, listOpts)
		if err != nil {
			return fail(err)
		}

		for _, candidate := range list.Items {
			cl := l.With("namespace", candidate.Namespace).
				With("name", candidate.Name)

			var flow configuration.FlowName
			if err := flow.Set(candidate.Labels[KubernetesLabelFlow]); err != nil || flow.IsZero() {
				cl.WithError(err).
					Warnf("pod does have an illegal %v label; this warn message will appear again until this is fixed; skipping...", KubernetesLabelFlow)
				continue
			}

			cl = cl.With("flow", flow)

			var sessionId session.Id
			if err := sessionId.Set(candidate.Labels[KubernetesLabelSessionId]); err != nil || flow.IsZero() {
				if ok, err := this.removePod(ctx, candidate.Namespace, candidate.Name, nil); err != nil {
					cl.WithError(err).
						Warn("cannot remove dead pod; this message might continue appearing until manually fixed; skipping...")
				} else if ok {
					cl.Info("pod without session id was removed removed")
				}
				continue
			} else if !sessionId.IsZero() {
				cl = cl.With("session", sessionId)
			}

			if flow.IsEqualTo(this.flow) {
				switch candidate.Status.Phase {
				case v1.PodPending, v1.PodRunning:
					ok, err := opts.HasSession(ctx, this.flow, sessionId)
					if err != nil {
						cl.WithError(err).
							Warn("cannot if the session of pod exists; this message might continue appearing until manually fixed; skipping...")
						continue
					}

					if ok != nil && !*ok {
						if ok, err := this.removePod(ctx, candidate.Namespace, candidate.Name, nil); err != nil {
							cl.WithError(err).
								Warn("cannot remove pod without valid session; this message might continue appearing until manually fixed; skipping...")
						} else if ok {
							cl.Info("pod without valid session removed")
						}
					} else {
						cl.Debug("found pod that is owned by this flow environment; ignoring...")
					}
				default:
					if ok, err := this.removePod(ctx, candidate.Namespace, candidate.Name, nil); err != nil {
						cl.WithError(err).
							Warn("cannot remove dead pod; this message might continue appearing until manually fixed; skipping...")
					} else if ok {
						cl.Info("dead pod removed")
					}
				}
				continue
			}

			globalHasFlow, err := opts.HasFlowOfName(flow)
			if err != nil {
				return fail(err)
			}

			if globalHasFlow {
				cl.Debug("found pod that is owned by another environment; ignoring...")
				continue
			}

			shouldBeCleaned, err := this.conf.CleanOrphan.Render(kubernetesPodContext{&candidate})
			if err != nil {
				return fail(err)
			}

			if !shouldBeCleaned {
				cl.Debug("found pod that isn't owned by anybody, but should be kept; ignoring...")
				continue
			}

			if ok, err := this.removePod(ctx, candidate.Namespace, candidate.Name, nil); err != nil {
				cl.WithError(err).
					Warn("cannot remove orphan pod; this message might continue appearing until manually fixed; skipping...")
				continue
			} else if ok {
				cl.Info("orphan pod removed")
			}
		}

		if list.Continue == "" {
			return nil
		}
		listOpts.Continue = list.Continue
	}
}

func (this *KubernetesRepository) logger() log.Logger {
	if v := this.Logger; v != nil {
		return v
	}
	return log.GetLogger("kubernetes-repository")
}

type kubernetesPodContext struct {
	*v1.Pod
}

func (this *kubernetesPodContext) GetField(name string) (any, bool, error) {
	switch name {
	case "namespace":
		return this.Namespace, true, nil
	case "name":
		return this.Name, true, nil
	case "image":
		for _, candidate := range this.Spec.Containers {
			if candidate.Name == "bifroest" {
				return candidate.Image, true, nil
			}
		}
		return nil, true, nil
	case "flow":
		if this.Labels == nil {
			return nil, true, nil
		}
		plain, ok := this.Labels[KubernetesLabelFlow]
		if !ok {
			return nil, true, nil
		}
		var flow configuration.FlowName
		if err := flow.Set(plain); err != nil {
			return nil, false, err
		}
		if flow.IsZero() {
			return nil, true, nil
		}
		return flow, true, nil
	default:
		return nil, false, fmt.Errorf("unknown field %q", name)
	}
}

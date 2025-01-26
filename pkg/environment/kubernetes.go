package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	gonet "net"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/echocat/slf4g"
	"github.com/moby/spdystream"
	v1 "k8s.io/api/core/v1"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	bkube "github.com/engity-com/bifroest/pkg/kubernetes"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
)

type kubernetes struct {
	repository *KubernetesRepository

	name      string
	namespace string
	sessionId session.Id

	remoteUser string
	remoteHost net.Host

	shellCommand []string
	execCommand  []string
	sftpCommand  []string
	user         string
	group        string
	directory    string

	portForwardingAllowed bool

	impSession imp.Session
	environ    sys.EnvVars

	owners atomic.Int32
}

func (this *kubernetes) SessionId() session.Id {
	return this.sessionId
}

func (this *kubernetes) PublicKey() crypto.PublicKey {
	return nil
}

func (this *kubernetes) Dial(ctx context.Context) (gonet.Conn, error) {
	return this.repository.client.DialPod(ctx, this.namespace, this.name, strconv.Itoa(imp.ServicePort))
}

func (this *KubernetesRepository) new(ctx context.Context, pod *v1.Pod, logger log.Logger) (*kubernetes, error) {
	fail := func(err error) (*kubernetes, error) {
		return nil, errors.System.Newf("cannot create environment from pod %v/%v of flow %v: %w", pod.Namespace, pod.Name, this.flow, err)
	}
	failf := func(msg string, args ...any) (*kubernetes, error) {
		return fail(errors.System.Newf(msg, args...))
	}

	result := &kubernetes{
		repository: this,
	}
	if err := result.parsePod(pod); err != nil {
		return failf("cannot parse pod: %w", err)
	}
	var err error
	if result.impSession, err = this.imp.Open(ctx, result); err != nil {
		return failf("cannot open IMP session: %w", err)
	}

	connId, err := connection.NewId()
	if err != nil {
		return failf("cannot create new connection ID: %w", err)
	}

	for try := 1; try <= 200; try++ {
		if environ, err := result.impSession.GetEnvironment(ctx, connId); err == nil {
			result.environ = environ
			break
		} else if errors.Is(err, io.EOF) ||
			errors.Is(err, io.ErrUnexpectedEOF) ||
			errors.Is(err, bkube.ErrEndpointNotFound) ||
			errors.Is(err, spdystream.ErrWriteClosedStream) ||
			errors.Is(err, spdystream.ErrReset) ||
			errors.Is(err, spdystream.ErrTimeout) ||
			errors.Is(err, spdystream.ErrInvalidStreamId) {
			// try waiting...
		} else {
			return failf("cannot get environment of created pod: %w", err)
		}
		l := logger.With("try", try)
		if try <= 2 {
			l.Debug("waiting for container's imp getting ready...")
		} else if try%30 == 0 {
			l.Info("still waiting for container's imp getting ready...")
		}
		time.Sleep(50 * time.Millisecond)
	}

	result.owners.Add(1)

	return result, nil
}

func (this *kubernetes) Dispose(ctx context.Context) (_ bool, rErr error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose environment: %w", err)
	}

	defer this.repository.sessionIdMutex.Lock(this.sessionId)()
	defer common.KeepError(&rErr, this.closeGuarded)

	ok, err := this.repository.removePod(ctx, this.namespace, this.name, nil)
	if err != nil {
		return fail(err)
	}

	return ok, nil
}

func (this *kubernetes) Close() (rErr error) {
	defer this.repository.sessionIdMutex.Lock(this.sessionId)()

	return this.closeGuarded()
}

func (this *kubernetes) closeGuarded() error {
	if this.owners.Add(-1) > 0 {
		return nil
	}
	this.repository.activeInstances.Delete(this.sessionId)
	return nil
}

func (this *kubernetes) isRelevantError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !sys.IsClosedError(err)
}

var (
	podContainsProblemsErr = errors.System.Newf("pod contains problems")
)

func (this *kubernetes) parsePod(pod *v1.Pod) (err error) {
	fail := func(err error) error {
		return fmt.Errorf("%w: %v", podContainsProblemsErr, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(errors.System.Newf(msg, args...))
	}
	decodeStrings := func(in string) (result []string, err error) {
		err = json.Unmarshal([]byte(in), &result)
		return result, err
	}

	this.name = pod.Name
	this.namespace = pod.Namespace

	labels := pod.Labels
	if labels == nil {
		pod.Labels = map[string]string{}
	}
	if v := labels[KubernetesLabelFlow]; v == "" {
		return failf("missing label %s", KubernetesLabelFlow)
	} else if v != this.repository.flow.String() {
		return failf("expected flow: %v; bot container had: %v", this.repository.flow, v)
	}
	if v := labels[KubernetesLabelSessionId]; v == "" {
		return failf("missing label %s", KubernetesLabelSessionId)
	} else if err = this.sessionId.UnmarshalText([]byte(v)); err != nil {
		return failf("cannot decode label %s: %w", KubernetesLabelSessionId, err)
	}

	annotations := pod.Annotations
	if annotations == nil {
		pod.Annotations = map[string]string{}
	}
	this.remoteUser = annotations[KubernetesAnnotationCreatedRemoteUser]
	if v := annotations[KubernetesAnnotationCreatedRemoteHost]; v == "" {
		return failf("missing annotation %s", KubernetesAnnotationCreatedRemoteHost)
	} else if err = this.remoteHost.Set(v); err != nil {
		return failf("cannot decode annotation %s: %w", KubernetesAnnotationCreatedRemoteHost, err)
	}
	if v := annotations[KubernetesAnnotationShellCommand]; v == "" {
		return failf("missing annotation %s", KubernetesAnnotationShellCommand)
	} else if this.shellCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode annotation %s: %w", KubernetesAnnotationShellCommand, err)
	} else if len(this.shellCommand) == 0 || len(this.shellCommand[0]) == 0 {
		return failf("illegal annotation value for %s", KubernetesAnnotationShellCommand)
	}
	if v := annotations[KubernetesAnnotationExecCommand]; v == "" {
		return failf("missing annotation %s", KubernetesAnnotationExecCommand)
	} else if this.execCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode annotation %s: %w", KubernetesAnnotationExecCommand, err)
	} else if len(this.execCommand) == 0 || len(this.execCommand[0]) == 0 {
		return failf("illegal annotation value for %s", KubernetesAnnotationExecCommand)
	}
	if v := annotations[KubernetesAnnotationSftpCommand]; v == "" {
		this.sftpCommand = nil
	} else if this.sftpCommand, err = decodeStrings(v); err != nil {
		return failf("cannot decode annotation %s: %w", KubernetesAnnotationSftpCommand, err)
	} else if len(this.sftpCommand) == 0 || len(this.sftpCommand[0]) == 0 {
		return failf("illegal annotation value for %s", KubernetesAnnotationSftpCommand)
	}

	this.user = annotations[KubernetesAnnotationUser]
	this.group = annotations[KubernetesAnnotationGroup]
	this.directory = annotations[KubernetesAnnotationDirectory]
	this.portForwardingAllowed = annotations[KubernetesAnnotationPortForwardingAllowed] == "true"

	return nil
}

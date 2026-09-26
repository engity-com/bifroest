package authorization

import (
	"context"
	"fmt"
	"reflect"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func NewAuthorizerFacade(ctx context.Context, flows *configuration.Flows) (*AuthorizerFacade, error) {
	return NewAuthorizerFacadeWithObserver(ctx, flows, nil)
}

func NewAuthorizerFacadeWithObserver(ctx context.Context, flows *configuration.Flows, observer FlowAuthorizationObserver) (*AuthorizerFacade, error) {
	if flows == nil {
		return &AuthorizerFacade{observer: observer}, nil
	}

	entries := make([]facaded, len(*flows))
	for i, flow := range *flows {
		if err := entries[i].newFrom(ctx, &flow); err != nil {
			return nil, err
		}
	}

	return &AuthorizerFacade{entries: entries, observer: observer}, nil
}

type AuthorizerFacade struct {
	entries  []facaded
	observer FlowAuthorizationObserver
}

type FlowAuthorizationMethod string

const (
	FlowAuthorizationMethodPublicKey           FlowAuthorizationMethod = "public-key"
	FlowAuthorizationMethodPassword            FlowAuthorizationMethod = "password"
	FlowAuthorizationMethodKeyboardInteractive FlowAuthorizationMethod = "keyboard-interactive"
)

type FlowAuthorizationPhase string

const (
	FlowAuthorizationPhaseCandidate FlowAuthorizationPhase = "candidate"
	FlowAuthorizationPhaseVerified  FlowAuthorizationPhase = "verified"
)

type FlowAuthorizationOutcome string

const (
	FlowAuthorizationOutcomeAccepted FlowAuthorizationOutcome = "accepted"
	FlowAuthorizationOutcomeDenied   FlowAuthorizationOutcome = "denied"
	FlowAuthorizationOutcomeFailed   FlowAuthorizationOutcome = "failed"
)

type FlowAuthorizationObservation struct {
	Flow              configuration.FlowName
	ConnectionId      string
	SessionId         string
	Method            FlowAuthorizationMethod
	Phase             FlowAuthorizationPhase
	Outcome           FlowAuthorizationOutcome
	AuthorizationKind string
	Err               error
}

type FlowAuthorizationObserver func(context.Context, FlowAuthorizationObservation) error

func (this *AuthorizerFacade) AuthorizePublicKey(req PublicKeyRequest) (Authorization, error) {
	_, isCertificate := req.RemotePublicKey().(*ssh.Certificate)
	phase := FlowAuthorizationPhaseCandidate
	if isPublicKeyVerified(req) {
		phase = FlowAuthorizationPhaseVerified
	}
	for _, candidate := range this.entries {
		if isCertificate {
			if _, supported := candidate.CloseableAuthorizer.(userCertificateAuthorizer); !supported {
				continue
			}
		}
		if ok, err := candidate.canHandle(req); err != nil {
			return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
		} else if ok {
			resp, err := candidate.AuthorizePublicKey(req)
			resp, err = validateFlowAuthorizationResponse(candidate.flow, resp, err)
			if observerErr := this.observe(req, candidate.flow, FlowAuthorizationMethodPublicKey, phase, resp, err); observerErr != nil {
				return nil, fmt.Errorf("[%v] %w", candidate.flow, observerErr)
			}
			if err != nil {
				return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
			}
			if resp.IsAuthorized() {
				return resp, nil
			}
		}
	}
	this.logNoMatchingFlow(req)
	return Forbidden(req.Connection().Remote()), nil
}

func (this *AuthorizerFacade) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	for _, candidate := range this.entries {
		if ok, err := candidate.canHandle(req); err != nil {
			return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
		} else if ok {
			resp, err := candidate.AuthorizePassword(req)
			resp, err = validateFlowAuthorizationResponse(candidate.flow, resp, err)
			if observerErr := this.observe(req, candidate.flow, FlowAuthorizationMethodPassword, "", resp, err); observerErr != nil {
				return nil, fmt.Errorf("[%v] %w", candidate.flow, observerErr)
			}
			if err != nil {
				return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
			}
			if resp.IsAuthorized() {
				return resp, nil
			}
		}
	}
	this.logNoMatchingFlow(req)
	return Forbidden(req.Connection().Remote()), nil
}

func (this *AuthorizerFacade) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	for _, candidate := range this.entries {
		if ok, err := candidate.canHandle(req); err != nil {
			return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
		} else if ok {
			resp, err := candidate.AuthorizeInteractive(req)
			resp, err = validateFlowAuthorizationResponse(candidate.flow, resp, err)
			if observerErr := this.observe(req, candidate.flow, FlowAuthorizationMethodKeyboardInteractive, "", resp, err); observerErr != nil {
				return nil, fmt.Errorf("[%v] %w", candidate.flow, observerErr)
			}
			if err != nil {
				return nil, fmt.Errorf("[%v] %w", candidate.flow, err)
			}
			if resp.IsAuthorized() {
				return resp, nil
			}
		}
	}
	this.logNoMatchingFlow(req)
	return Forbidden(req.Connection().Remote()), nil
}

func (this *AuthorizerFacade) logNoMatchingFlow(req Request) {
	for _, candidate := range this.entries {
		matches, err := candidate.canHandle(req)
		if err != nil || matches {
			return
		}
	}
	req.Connection().Logger().Debug("no flow matches requested user")
}

func validateFlowAuthorizationResponse(flow configuration.FlowName, auth Authorization, err error) (Authorization, error) {
	if err != nil {
		return auth, err
	}
	if auth == nil {
		return nil, errors.System.Newf("authorization flow returned a nil response")
	}
	if auth.IsAuthorized() && auth.Flow() != flow {
		return nil, errors.System.Newf("authorization flow returned response for flow %q", auth.Flow())
	}
	return auth, nil
}

func (this *AuthorizerFacade) observe(req Request, flow configuration.FlowName, method FlowAuthorizationMethod, phase FlowAuthorizationPhase, auth Authorization, authErr error) error {
	if this.observer == nil {
		return nil
	}
	observation := FlowAuthorizationObservation{
		Flow:         flow,
		ConnectionId: req.Connection().Id().String(),
		Method:       method,
		Phase:        phase,
		Err:          authErr,
	}
	switch {
	case authErr != nil:
		observation.Outcome = FlowAuthorizationOutcomeFailed
	case auth.IsAuthorized():
		observation.Outcome = FlowAuthorizationOutcomeAccepted
	default:
		observation.Outcome = FlowAuthorizationOutcomeDenied
	}
	if auth != nil {
		observation.AuthorizationKind = KindOf(auth)
		if sess := auth.FindSession(); sess != nil {
			observation.SessionId = sess.Id().String()
		}
	}
	return this.observer(req.Context(), observation)
}

func (this *AuthorizerFacade) RestoreFromSession(ctx context.Context, sess session.Session, opts *RestoreOpts) (Authorization, error) {
	for _, candidate := range this.entries {
		auth, err := candidate.RestoreFromSession(ctx, sess, opts)
		if errors.Is(err, ErrNoSuchAuthorization) {
			continue
		}
		if err != nil {
			return auth, fmt.Errorf("[%v] %w", candidate.flow, err)
		}
		return auth, nil
	}
	return nil, ErrNoSuchAuthorization
}

func (this *AuthorizerFacade) Close() (rErr error) {
	defer func() { this.entries = nil }()
	for _, candidate := range this.entries {
		//goland:noinspection GoDeferInLoop
		defer common.KeepCloseError(&rErr, candidate)
	}
	return nil
}

type facaded struct {
	CloseableAuthorizer

	flow        configuration.FlowName
	requirement *configuration.Requirement
}

func (this *facaded) newFrom(ctx context.Context, flow *configuration.Flow) error {
	fail := func(err error) error {
		return fmt.Errorf("cannot initizalize authorization for flow %q: %w", flow.Name, err)
	}

	factory, ok := configurationTypeToAuthorizerFactory[reflect.TypeOf(flow.Authorization.V)]
	if !ok {
		return fail(errors.Config.Newf("cannot handle authorization type %v", reflect.TypeOf(flow.Authorization.V)))
	}
	m := reflect.ValueOf(factory)
	rets := m.Call([]reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(flow.Name), reflect.ValueOf(flow.Authorization.V)})
	if err, ok := rets[1].Interface().(error); ok && err != nil {
		return fail(err)
	}
	this.CloseableAuthorizer = rets[0].Interface().(CloseableAuthorizer)
	this.requirement = &flow.Requirement
	this.flow = flow.Name
	return nil
}

func (this *facaded) canHandle(req Request) (bool, error) {
	incl, excl := this.requirement.IncludedRequestingName, this.requirement.ExcludedRequestingName

	if !incl.IsZero() && !incl.MatchString(req.Connection().Remote().User()) {
		return false, nil
	}
	if !excl.IsZero() && excl.MatchString(req.Connection().Remote().User()) {
		return false, nil
	}

	return true, nil
}

var (
	configurationTypeToAuthorizerFactory = make(map[reflect.Type]any)
)

type AuthorizerFactory[C any, A CloseableAuthorizer] func(ctx context.Context, flow configuration.FlowName, conf C) (A, error)

func RegisterAuthorizer[C any, A CloseableAuthorizer](factory AuthorizerFactory[C, A]) AuthorizerFactory[C, A] {
	ct := reflect.TypeFor[C]()
	configurationTypeToAuthorizerFactory[ct] = factory
	return factory
}

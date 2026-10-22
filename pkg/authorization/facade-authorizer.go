package authorization

import (
	"context"
	"fmt"
	"reflect"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
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

	return &AuthorizerFacade{entries: entries, flows: append(configuration.Flows(nil), (*flows)...), observer: observer}, nil
}

type AuthorizerFacade struct {
	entries  []facaded
	flows    configuration.Flows
	observer FlowAuthorizationObserver
}

func (this *AuthorizerFacade) OidcRefreshAuthorizer(flow configuration.FlowName) *OidcDeviceAuthAuthorizer {
	for _, entry := range this.entries {
		if entry.flow == flow {
			authorizer, _ := entry.CloseableAuthorizer.(*OidcDeviceAuthAuthorizer)
			return authorizer
		}
	}
	return nil
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
	selection, candidates, err := this.candidatesFor(req)
	if err != nil {
		return nil, err
	}
	_, isCertificate := req.RemotePublicKey().(*ssh.Certificate)
	phase := FlowAuthorizationPhaseCandidate
	if isPublicKeyVerified(req) {
		phase = FlowAuthorizationPhaseVerified
	}
	for _, candidate := range candidates {
		if isCertificate {
			if _, supported := candidate.CloseableAuthorizer.(userCertificateAuthorizer); !supported {
				continue
			}
		}
		if ok, err := candidate.canHandle(req, selection); err != nil {
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
	this.logNoMatchingFlow(req, selection, candidates)
	return Forbidden(req.Connection().Remote()), nil
}

func (this *AuthorizerFacade) AuthorizePassword(req PasswordRequest) (Authorization, error) {
	selection, candidates, err := this.candidatesFor(req)
	if err != nil {
		return nil, err
	}
	for _, candidate := range candidates {
		if ok, err := candidate.canHandle(req, selection); err != nil {
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
	this.logNoMatchingFlow(req, selection, candidates)
	return Forbidden(req.Connection().Remote()), nil
}

func (this *AuthorizerFacade) AuthorizeInteractive(req InteractiveRequest) (Authorization, error) {
	selection, candidates, err := this.candidatesFor(req)
	if err != nil {
		return nil, err
	}
	for _, candidate := range candidates {
		if ok, err := candidate.canHandle(req, selection); err != nil {
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
	this.logNoMatchingFlow(req, selection, candidates)
	return Forbidden(req.Connection().Remote()), nil
}

func (this *AuthorizerFacade) logNoMatchingFlow(req Request, selection connection.Selection, candidates []facaded) {
	for _, candidate := range candidates {
		matches, err := candidate.canHandle(req, selection)
		if err != nil || matches {
			return
		}
	}
	req.Connection().Logger().Debug("no flow matches requested user")
}

// Resolve the logical request once. A fixed published slug narrows the entire
// attempt, including every authentication method, to exactly that flow. Failed
// requirements or rejected credentials must not expose a generic fallback flow.
func (this *AuthorizerFacade) candidatesFor(req Request) (connection.Selection, []facaded, error) {
	selection, err := connection.SelectionOf(req)
	if err != nil {
		return connection.Selection{}, nil, err
	}
	if selection.Transport == connection.TransportHttp {
		flow, fixed, err := this.flows.ResolveHttpSlug(selection.Host, selection.Slug)
		if err != nil {
			return connection.Selection{}, nil, err
		}
		if fixed {
			for index := range this.entries {
				if this.entries[index].flow == flow {
					return selection, this.entries[index : index+1], nil
				}
			}
			return connection.Selection{}, nil, errors.System.Newf("published HTTP flow has no authorizer")
		}
	}
	return selection, this.entries, nil
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
	ssh         configuration.FlowSsh
	http        configuration.FlowHttp
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
	this.ssh = flow.Ssh
	this.http = flow.Http
	return nil
}

func (this *facaded) canHandle(req Request, selection connection.Selection) (bool, error) {
	name := req.Connection().Remote().User()
	switch selection.Transport {
	case connection.TransportSsh:
		return this.ssh.IsEnabled() && this.requirement.MatchesSsh(name), nil
	case connection.TransportHttp:
		if !this.http.IsEnabled() {
			return false, nil
		}
		if !this.http.RequestUserEnabled() && name != "" {
			return false, nil
		}
		return this.requirement.MatchesHttp(name, selection.Host, selection.Slug), nil
	default:
		return false, errors.User.Newf("unsupported incoming transport")
	}
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

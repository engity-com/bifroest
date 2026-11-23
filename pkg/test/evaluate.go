package test

import (
	"bytes"
	"context"
	"io"
	"strings"

	log "github.com/echocat/slf4g"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"

	"github.com/engity-com/bifroest/pkg/authentication"
	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/connection"
	"github.com/engity-com/bifroest/pkg/environment"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/net"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

const scope = "post-authentication/session-target"

func loadConfiguration(source []byte) (*configuration.Configuration, error) {
	if len(source) > maxSource {
		return nil, invalid("configuration source limit exceeded")
	}
	// Reject aliases and admit local environments before production decoding can
	// copy host-dependent defaults into controlled values. No alternate defaults
	// are invented. Import-time globals are not exposed to the Lua views.
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(source))
	if decoder.Decode(&document) != nil {
		return nil, invalid("invalid YAML configuration")
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return nil, invalid("exactly one YAML document is required")
	}
	nodes := maxNodes
	var inspect func(*yaml.Node, bool, int) error
	inspect = func(n *yaml.Node, env bool, depth int) error {
		nodes--
		if nodes < 0 || depth > 32 || n.Kind == yaml.AliasNode {
			return invalid("unsupported YAML structure or alias")
		}
		if n.Kind == yaml.MappingNode {
			for i := 0; i < len(n.Content); i += 2 {
				key, value := n.Content[i], n.Content[i+1]
				if key.Value == "<<" {
					return invalid("YAML merges are not supported in the offline slice")
				}
				// Match the production environment decoder's type selection before
				// host-dependent local defaults can enter controlled configuration.
				if env && key.Value == "type" && strings.ToLower(value.Value) == "local" {
					if err := admitLocalConfiguration(n); err != nil {
						return err
					}
				}
				if err := inspect(value, env || key.Value == "environment" || key.Value == "environments", depth+1); err != nil {
					return err
				}
			}
		} else {
			for _, child := range n.Content {
				if err := inspect(child, env, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := inspect(&document, false, 0); err != nil {
		return nil, err
	}
	conf := new(configuration.Configuration)
	if err := conf.LoadFromYaml(bytes.NewReader(source), "<offline>"); err != nil {
		return nil, err
	}
	if len(conf.Flows) > 32 {
		return nil, invalid("flow count limit exceeded")
	}
	return conf, nil
}

// evaluate shares the production facade, principal mapping and target projection.
// Its only authorizers are explicit assumed-result adapters owned by this runner.
func evaluate(ctx context.Context, conf *configuration.Configuration, rawInput, rawFacts any) (map[string]any, error) {
	var in input
	var world facts
	if err := validateRequestStrings(rawInput); err != nil {
		return nil, err
	}
	if err := decodeData(rawInput, &in); err != nil {
		return nil, err
	}
	// JSON would serialize an integral float as an integer. Do not let that
	// silently coerce Lua fixture field types at this schema boundary.
	if err := validateFactIntegers(rawFacts); err != nil {
		return nil, err
	}
	if err := decodeData(rawFacts, &world); err != nil {
		return nil, err
	}
	request, err := newOfflineRequest(ctx, in.Request)
	if err != nil {
		return nil, err
	}
	for name, assumed := range in.Authentication {
		var configured *configuration.Flow
		for i := range conf.Flows {
			if string(conf.Flows[i].Name) == name {
				configured = &conf.Flows[i]
				break
			}
		}
		if configured == nil || (assumed.Outcome != "allow" && assumed.Outcome != "deny") {
			return nil, invalid("invalid or unknown flow authentication assumption")
		}
		if configuration.OidcSettings(configured.Authorization.V) != nil {
			validMode := assumed.Mode == "" || assumed.Mode == "verified-oidc"
			missingIdentity := assumed.Outcome == "allow" && (assumed.Mode != "verified-oidc" || assumed.Oidc == nil)
			contradictoryDenial := assumed.Outcome == "deny" && assumed.Oidc != nil
			if assumed.Account != "" || !validMode || missingIdentity || contradictoryDenial {
				return nil, invalid("invalid OIDC authentication assumption")
			}
			continue
		}
		validMode := assumed.Mode == "" || assumed.Mode == "post-authentication" || assumed.Mode == "mapped-local"
		missingAccount := assumed.Outcome == "allow" && assumed.Account == "" && assumed.Mode != "mapped-local"
		if !validMode || missingAccount || assumed.Oidc != nil {
			return nil, invalid("invalid or unknown flow authentication assumption")
		}
	}
	accounts, err := newAccountInventory(world)
	if err != nil {
		return nil, err
	}
	facade, err := authorization.NewAuthorizerFacadeWithFactory(ctx, &conf.Flows, func(_ context.Context, flow *configuration.Flow) (authorization.DiscoveryAuthorizer, error) {
		return &assumedAuthorizer{flow: flow, in: in, bind: accounts.bind}, nil
	}, nil)
	if err != nil {
		return nil, err
	}
	defer facade.Close() // These adapters hold no external resources.
	var selected authorization.Authorization
	if request.method == authorization.LoginMethodKeyboardInteractive || request.method == authorization.LoginMethodOidc {
		selected, err = facade.AuthorizeInteractive(request)
	} else {
		selected, err = facade.AuthorizePassword(request)
	}
	if err != nil {
		return nil, err
	}
	if !selected.IsAuthorized() {
		return map[string]any{"scope": scope, "decision": "deny", "authenticationAssumed": true, "request": request.view()}, nil
	}
	var flow *configuration.Flow
	for i := range conf.Flows {
		if conf.Flows[i].Name == selected.Flow() {
			flow = &conf.Flows[i]
			break
		}
	}
	if flow == nil {
		return nil, errors.System.Newf("selected flow is unavailable")
	}
	if err := admitTemplate(flow.Authorization.Principal.String()); err != nil {
		return nil, err
	}
	controlled := &policyContext{offlineRequest: request, auth: selected, evaluation: request.evaluation, flow: flow, accounts: accounts}
	identity, err := authorization.AuthenticationWithPrincipal(selected, conf.Flows, func(original authentication.Identity) authorization.PrincipalMappingContext {
		copyOfContext := *controlled
		copyOfContext.identity = original
		return &copyOfContext
	})
	if err != nil {
		return nil, err
	}
	controlled.identity = identity
	var target map[string]any
	switch targetConf := flow.Environment.V.(type) {
	case *configuration.EnvironmentSsh:
		if targetConf == nil {
			return nil, invalid("selected target configuration is unavailable")
		}
		for _, source := range []string{targetConf.Address.String(), targetConf.User.String(), targetConf.PortForwardingAllowed.String(), targetConf.ReversePortForwardingAllowed.String()} {
			if err := admitTemplate(source); err != nil {
				return nil, err
			}
		}
		projection, err := environment.ProjectSshTarget(controlled, targetConf)
		if err != nil {
			return nil, err
		}
		target = map[string]any{"type": "ssh"}
		for _, name := range []string{"address", "user", "portForwardingAllowed", "reversePortForwardingAllowed"} {
			value, present := projection.Field(name)
			if !present {
				return nil, errors.System.Newf("target projection field unavailable")
			}
			target[name] = value
		}
	case *configuration.EnvironmentLocal:
		if targetConf == nil {
			return nil, invalid("selected target configuration is unavailable")
		}
		if err := admitTemplate(targetConf.LoginAllowed.String()); err != nil {
			return nil, err
		}
		allowed, err := environment.LocalLoginAllowed(controlled, targetConf)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return map[string]any{"scope": scope, "decision": "deny", "flow": string(flow.Name), "authenticationAssumed": true, "stage": "local-login", "identity": identityFields(identity), "request": request.view()}, nil
		}
		target, err = accounts.projectLocal(controlled, targetConf)
		if err != nil {
			return nil, err
		}
	default:
		return nil, invalid("selected target type is outside the offline slice")
	}
	auth, ok := selected.(*assumedAuthorization)
	if !ok {
		return nil, errors.System.Newf("selected assumed authentication is unavailable")
	}
	original, err := auth.Authentication()
	if err != nil {
		return nil, err
	}
	authenticationView := map[string]any{"mode": auth.mode, "account": original.Principal}
	if auth.oidc != nil {
		authenticationView = map[string]any{"mode": auth.mode, "issuer": original.Issuer, "subject": original.Subject}
	}
	if auth.mode == "mapped-local" {
		authenticationView["remoteName"] = auth.mappedName
	}
	return map[string]any{"scope": scope, "decision": "selected", "flow": string(flow.Name), "authenticationAssumed": true,
		"identity": identityFields(identity), "environment": target, "authentication": authenticationView, "request": request.view()}, nil
}

type binder func(context.Context, *configuration.Flow, string) (*authorization.AssumedLocalAuthentication, error)

type assumedAuthorizer struct {
	flow *configuration.Flow
	in   input
	bind binder
}

func (this *assumedAuthorizer) AuthorizePassword(req authorization.PasswordRequest) (authorization.Authorization, error) {
	if configuration.OidcSettings(this.flow.Authorization.V) != nil {
		// Product OIDC authorizers never accept passwords, even if a successful
		// interactive result was supplied for the same configured flow.
		return authorization.Forbidden(req.Connection().Remote()), nil
	}
	return this.authorizeLocal(req)
}

func (this *assumedAuthorizer) authorizeLocal(req authorization.Request) (authorization.Authorization, error) {
	conf, ok := this.flow.Authorization.V.(*configuration.AuthorizationLocal)
	if !ok || conf == nil {
		return nil, invalid("attempted authentication type is outside the offline slice")
	}
	assumed, known := this.in.Authentication[string(this.flow.Name)]
	if !known {
		return nil, invalid("authentication outcome was not modeled for attempted flow")
	}
	mode := assumed.Mode
	if mode == "" {
		mode = "post-authentication"
	}
	accountName := assumed.Account
	mappedName := ""
	if mode == "mapped-local" {
		// Only the requesting user is modeled at this pre-authentication boundary.
		// Reject other fields before the production wrapper could expose a zero
		// host/connection value as though it were a supplied observation.
		if err := admitTemplateFields(conf.RemoteName.String(), func(fields []string) error {
			if len(fields) == 2 && fields[0] == "remote" && fields[1] == "user" {
				return nil
			}
			return invalid("remoteName request field was not modeled")
		}); err != nil {
			return nil, err
		}
		var err error
		mappedName, err = authorization.ResolveRemoteName(req, conf.RemoteName)
		if err != nil {
			return nil, errors.Config.Newf("cannot resolve modeled local account: %w", err)
		}
		if accountName == "" {
			accountName = mappedName
		} else if !mappedAccountMatches(mappedName, accountName) {
			return nil, invalid("assumed account does not match the resolved local remoteName")
		}
	}
	if assumed.Outcome == "deny" {
		return authorization.Forbidden(req.Connection().Remote()), nil
	}
	bound, err := this.bind(req.Context(), this.flow, accountName)
	if err != nil {
		return nil, err
	}
	return &assumedAuthorization{bound: bound, remote: req.Connection().Remote(), mode: mode, mappedName: mappedName}, nil
}
func (*assumedAuthorizer) AuthorizePublicKey(authorization.PublicKeyRequest) (authorization.Authorization, error) {
	return nil, invalid("public-key simulation is unsupported")
}
func (this *assumedAuthorizer) AuthorizeInteractive(req authorization.InteractiveRequest) (authorization.Authorization, error) {
	if configuration.OidcSettings(this.flow.Authorization.V) == nil {
		return this.authorizeLocal(req)
	}
	assumed, known := this.in.Authentication[string(this.flow.Name)]
	if !known {
		return nil, invalid("authentication outcome was not modeled for attempted flow")
	}
	if assumed.Outcome == "deny" {
		return authorization.Forbidden(req.Connection().Remote()), nil
	}
	conf := configuration.OidcSettings(this.flow.Authorization.V)
	if err := admitTemplateFields(conf.Issuer.String(), func([]string) error { return invalid("OIDC issuer configuration fields were not modeled") }); err != nil {
		return nil, err
	}
	bound, err := authorization.BindAssumedOidcAuthentication(this.flow, *assumed.Oidc, req)
	if err != nil {
		return nil, err
	}
	return &assumedAuthorization{oidc: bound, remote: req.Connection().Remote(), mode: "verified-oidc"}, nil
}
func (*assumedAuthorizer) RestoreFromSession(context.Context, session.Session, *authorization.RestoreOpts) (authorization.Authorization, error) {
	return nil, invalid("session restoration is unsupported")
}
func (*assumedAuthorizer) Close() error { return nil }
func (this *assumedAuthorizer) AuthenticationCapabilities(in authorization.DiscoveryInput) authorization.AuthenticationCapabilities {
	if conf := configuration.OidcSettings(this.flow.Authorization.V); conf != nil {
		return authorization.OidcAuthenticationCapabilities(conf, this.CodeConfiguration() != nil, in)
	}
	if conf, ok := this.flow.Authorization.V.(*configuration.AuthorizationLocal); ok {
		return authorization.LocalAuthenticationCapabilities(conf, in)
	}
	// Unsupported attempted authorizers must remain errors, not an invented
	// negative capability that makes an unmodeled dependency look like denial.
	return authorization.AuthenticationCapabilities{KeyboardInteractive: true, OidcAuthorizationCode: true}
}

func (this *assumedAuthorizer) CodeConfiguration() *configuration.AuthorizationOidcAuthorizationCode {
	conf, _ := this.flow.Authorization.V.(*configuration.AuthorizationOidcAuthorizationCode)
	return conf
}

type assumedAuthorization struct {
	bound            *authorization.AssumedLocalAuthentication
	oidc             *authorization.AssumedOidcAuthentication
	remote           net.Remote
	mode, mappedName string
}

func (this *assumedAuthorization) IsAuthorized() bool { return true }
func (this *assumedAuthorization) Authentication() (authentication.Identity, error) {
	if this.oidc != nil {
		return this.oidc.Authentication()
	}
	return this.bound.Authentication()
}
func (this *assumedAuthorization) Flow() configuration.FlowName {
	if this.oidc != nil {
		return this.oidc.Flow()
	}
	return this.bound.Flow()
}
func (this *assumedAuthorization) Remote() net.Remote              { return this.remote }
func (*assumedAuthorization) EnvVars() sys.EnvVars                 { return nil }
func (*assumedAuthorization) FindSession() session.Session         { return nil }
func (*assumedAuthorization) FindSessionsPublicKey() ssh.PublicKey { return nil }
func (*assumedAuthorization) Dispose(context.Context) (bool, error) {
	return false, invalid("assumed authentication cannot dispose a session")
}

type offlineRequest struct {
	ctx        context.Context
	name       string
	evaluation *template.Evaluation
	selection  connection.Selection
	origin     string
	method     authorization.LoginMethod
}

func (this *offlineRequest) TemplateEvaluation() *template.Evaluation { return this.evaluation }

func (this *offlineRequest) Context() context.Context { return this.ctx }
func (this *offlineRequest) Connection() connection.Connection {
	return offlineConnection{name: this.name}
}
func (*offlineRequest) Sessions() session.Repository { return nil }
func (*offlineRequest) Validate(authorization.Authorization) (bool, error) {
	return false, invalid("no native validation is available")
}
func (*offlineRequest) RemotePassword() string { return "" }
func (*offlineRequest) SendInfo(string) error {
	return invalid("offline authentication cannot send interactive messages")
}
func (*offlineRequest) SendError(string) error {
	return invalid("offline authentication cannot send interactive messages")
}
func (*offlineRequest) Prompt(string, bool) (string, error) {
	return "", invalid("offline authentication cannot prompt")
}

type offlineConnection struct{ name string }

func (this offlineConnection) Id() connection.Id  { return connection.Id{} }
func (this offlineConnection) Remote() net.Remote { return offlineRemote{this.name} }
func (offlineConnection) Logger() log.Logger      { return log.GetLogger("offline-policy") }

type offlineRemote struct{ name string }

func (this offlineRemote) User() string { return this.name }
func (offlineRemote) Host() net.Host    { return net.Host{} }
func (offlineRemote) String() string    { return "offline" }

type policyContext struct {
	*offlineRequest
	auth       authorization.Authorization
	identity   authentication.Identity
	evaluation *template.Evaluation
	flow       *configuration.Flow
	accounts   accountInventory
}

func (this *policyContext) Authorization() authorization.Authorization { return this.auth }
func (this *policyContext) TemplateEvaluation() *template.Evaluation   { return this.evaluation }
func identityFields(identity authentication.Identity) map[string]any {
	return map[string]any{"principal": identity.Principal, "issuer": identity.Issuer, "subject": identity.Subject}
}
func (this *policyContext) GetField(name string) (any, bool, error) {
	switch name {
	case "remote":
		return map[string]any{"user": this.name}, true, nil
	case "authentication":
		return identityFields(this.identity), true, nil
	case "authorization":
		assumed, ok := this.auth.(*assumedAuthorization)
		if !ok {
			return nil, false, invalid("assumed authorization data unavailable")
		}
		if assumed.oidc != nil {
			return assumed.oidc, true, nil
		}
		view, err := this.accounts.management(this.ctx, this.flow, assumed.bound)
		return map[string]any{"user": view}, true, err
	default:
		return nil, false, invalid("policy context field was not modeled")
	}
}

func configurationView(conf *configuration.Configuration) any {
	flows := make([]any, 0, len(conf.Flows))
	for _, flow := range conf.Flows {
		flows = append(flows, map[string]any{"name": string(flow.Name)})
	}
	return map[string]any{"flows": flows}
}

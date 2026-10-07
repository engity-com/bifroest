package environment

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"

	essh "github.com/engity-com/ssh-server-go"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
)

func NewRepositoryFacade(ctx context.Context, flows *configuration.Flows, ap alternatives.Provider, i imp.Imp) (*RepositoryFacade, error) {
	return newRepositoryFacade(ctx, flows, ap, i)
}

func NewRepositoryFacadeWithHostKeys(ctx context.Context, flows *configuration.Flows, ap alternatives.Provider, i imp.Imp, hostKeys []crypto.PrivateKey, sessions ...session.Repository) (*RepositoryFacade, error) {
	deps := repositoryDependencies{hostKeys: hostKeys}
	if len(sessions) > 0 {
		deps.localAccounts = &localAccountCoordinator{sessions: sessions[0]}
	}
	ctx = context.WithValue(ctx, repositoryDependenciesContextKey{}, deps)
	return newRepositoryFacade(ctx, flows, ap, i)
}

func NewRepositoryFacadeWithManagement(ctx context.Context, flows *configuration.Flows, ap alternatives.Provider, i imp.Imp, hostKeys []crypto.PrivateKey, sessions session.Repository, management ManagementCommandRunner) (*RepositoryFacade, error) {
	ctx = context.WithValue(ctx, repositoryDependenciesContextKey{}, repositoryDependencies{
		hostKeys: hostKeys, localAccounts: &localAccountCoordinator{sessions: sessions}, management: management,
	})
	return newRepositoryFacade(ctx, flows, ap, i)
}

func newRepositoryFacade(ctx context.Context, flows *configuration.Flows, ap alternatives.Provider, i imp.Imp) (*RepositoryFacade, error) {
	if flows == nil {
		return &RepositoryFacade{}, nil
	}

	entries := make(map[configuration.FlowName]CloseableRepository, len(*flows))
	success := false
	defer func() {
		if !success {
			for _, entry := range entries {
				_ = entry.Close()
			}
		}
	}()
	for _, flow := range *flows {
		if _, exists := entries[flow.Name]; exists {
			return nil, fmt.Errorf("duplicate flow name %q", flow.Name)
		}
		instance, err := newInstance(ctx, &flow, ap, i)
		if err != nil {
			return nil, err
		}
		entries[flow.Name] = instance
	}

	success = true
	return &RepositoryFacade{entries}, nil
}

type RepositoryFacade struct {
	entries map[configuration.FlowName]CloseableRepository
}

func (this *RepositoryFacade) WillBeAccepted(ctx Context) (bool, error) {
	flow := ctx.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return false, fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	return candidate.WillBeAccepted(ctx)
}

func (this *RepositoryFacade) DoesSupportPty(ctx Context, pty essh.Pty) (bool, error) {
	flow := ctx.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return false, fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	return candidate.DoesSupportPty(ctx, pty)
}

func (this *RepositoryFacade) Ensure(req Request) (Environment, error) {
	flow := req.Authorization().Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return nil, fmt.Errorf("does not find valid environment for flow %v", flow)
	}
	if sess := req.Authorization().FindSession(); sess != nil {
		matches, err := this.SessionEnvironmentMatches(req.Context(), sess)
		if err != nil {
			return nil, err
		}
		if !matches {
			return nil, fmt.Errorf("session %s has a token from a different or unrecognized environment; operator inspection required", sess)
		}
	}
	return candidate.Ensure(req)
}

func (this *RepositoryFacade) FindBySession(ctx context.Context, sess session.Session, opts *FindOpts) (Environment, error) {
	flow := sess.Flow()
	candidate, ok := this.entries[flow]
	if !ok {
		return nil, ErrNoSuchEnvironment
	}
	matches, err := this.SessionEnvironmentMatches(ctx, sess)
	if err != nil {
		return nil, err
	}
	if !matches {
		return nil, fmt.Errorf("session %s has a token from a different or unrecognized environment; operator inspection required", sess)
	}
	return candidate.FindBySession(ctx, sess, opts)
}

// SessionEnvironmentMatches leaves unknown persisted tokens for operator review.
func (this *RepositoryFacade) SessionEnvironmentMatches(ctx context.Context, sess session.Session) (bool, error) {
	candidate, ok := this.entries[sess.Flow()]
	if !ok {
		return false, nil
	}
	raw, err := sess.EnvironmentToken(ctx)
	if err != nil {
		return false, fmt.Errorf("cannot inspect environment token of session %s: %w", sess, err)
	}
	if len(raw) == 0 {
		return true, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false, nil
	}
	if schema, present := fields["schema"]; present {
		var marker string
		if err := json.Unmarshal(schema, &marker); err != nil || marker != sshUserCertificateSchema || len(fields["user"]) != 0 {
			return false, nil
		}
		_, ok := candidate.(*SshRepository)
		return ok, nil
	}
	if user, present := fields["user"]; present {
		encoded, present := fields["portForwardingAllowed"]
		if !present || (string(encoded) != "true" && string(encoded) != "false") {
			return false, nil
		}
		for key := range fields {
			switch key {
			case "user", "version", "portForwardingAllowed":
			case "managed", "managedGroup", "managedGroupSid", "allowSystemUsers", "deleteOnDispose", "deleteProfileOnDispose", "killProcessesOnDispose", "processesKilledOnDispose":
				if runtime.GOOS != "windows" {
					return false, nil
				}
			default:
				return false, nil
			}
		}
		var identity struct {
			Name string          `json:"name"`
			UID  json.RawMessage `json:"uid"`
			SID  string          `json:"sid"`
		}
		if err := json.Unmarshal(user, &identity); err != nil {
			return false, nil
		}
		if version, present := fields["version"]; present {
			var number uint8
			if err := json.Unmarshal(version, &number); err != nil || number != 2 {
				return false, nil
			}
			if identity.Name == "" || (runtime.GOOS == "windows" && identity.SID == "") ||
				(runtime.GOOS != "windows" && (len(identity.UID) == 0 || string(identity.UID) == "null")) {
				return false, nil
			}
		} else if runtime.GOOS == "windows" ||
			(identity.Name == "" && (len(identity.UID) == 0 || string(identity.UID) == "null")) {
			return false, nil
		}
		_, ok := candidate.(*LocalRepository)
		return ok, nil
	}
	if runtime.GOOS == "windows" && len(fields) == 1 {
		if encoded, present := fields["portForwardingAllowed"]; present {
			var allowed bool
			if json.Unmarshal(encoded, &allowed) == nil {
				_, ok := candidate.(*LocalRepository)
				return ok, nil
			}
		}
	}
	return false, nil
}

// DisposeSession serializes local session disposal with account provisioning.
func (this *RepositoryFacade) DisposeSession(ctx context.Context, sess session.Session) (bool, error) {
	if local, ok := this.entries[sess.Flow()].(*LocalRepository); ok && local.coordinator != nil {
		local.coordinator.mu.Lock()
		defer local.coordinator.mu.Unlock()
	}
	matches, err := this.SessionEnvironmentMatches(ctx, sess)
	if err != nil {
		return false, err
	}
	if !matches {
		return false, fmt.Errorf("session %s has a token from a different or unrecognized environment; operator inspection required", sess)
	}
	return sess.Dispose(ctx)
}

func (this *RepositoryFacade) IsSessionCompatible(ctx context.Context, sess session.Session) (bool, error) {
	if sess == nil {
		return false, nil
	}
	candidate, ok := this.entries[sess.Flow()]
	if !ok {
		return false, nil
	}
	if matches, err := this.SessionEnvironmentMatches(ctx, sess); err != nil || !matches {
		return false, err
	}
	checker, ok := candidate.(SessionCompatibilityChecker)
	if !ok {
		return true, nil
	}
	return checker.IsSessionCompatible(ctx, sess)
}

func (this *RepositoryFacade) IsSessionCompatibleWith(ctx Context, sess session.Session) (bool, error) {
	if sess == nil {
		return false, nil
	}
	candidate, ok := this.entries[sess.Flow()]
	if !ok {
		return false, nil
	}
	if matches, err := this.SessionEnvironmentMatches(ctx.Context(), sess); err != nil || !matches {
		return false, err
	}
	checker, ok := candidate.(ContextualSessionCompatibilityChecker)
	if !ok {
		return true, nil
	}
	return checker.IsSessionCompatibleWith(ctx, sess)
}

// ImpProtocolCompatibility inspects the session's resource without opening IMP
// or disposing the resource or session. Non-IMP flows have no IMP resource.
func (this *RepositoryFacade) ImpProtocolCompatibility(ctx context.Context, sess session.Session) (compatible bool, found bool, revision uint32, identity ResourceIdentity, err error) {
	if sess == nil {
		return false, false, 0, ResourceIdentity{}, nil
	}
	candidate, ok := this.entries[sess.Flow()]
	if !ok {
		return false, false, 0, ResourceIdentity{}, nil
	}
	matches, err := this.SessionEnvironmentMatches(ctx, sess)
	if err != nil {
		return false, false, 0, ResourceIdentity{}, err
	}
	if !matches {
		return false, false, 0, ResourceIdentity{}, fmt.Errorf("session %s has a token from a different or unrecognized environment; operator inspection required", sess)
	}
	checker, ok := candidate.(ImpProtocolCompatibilityChecker)
	if !ok {
		return true, false, 0, ResourceIdentity{}, nil
	}
	return checker.ImpProtocolCompatibility(ctx, sess)
}

func (this *RepositoryFacade) Close() (rErr error) {
	for _, entity := range this.entries {
		//goland:noinspection GoDeferInLoop
		defer common.KeepCloseError(&rErr, entity)
	}
	return nil
}

func (this *RepositoryFacade) Cleanup(ctx context.Context, opts *CleanupOpts) error {
	for _, entity := range this.entries {
		if err := entity.Cleanup(ctx, opts); err != nil {
			return err
		}
	}
	return nil
}

func newInstance(ctx context.Context, flow *configuration.Flow, ap alternatives.Provider, i imp.Imp) (env CloseableRepository, err error) {
	fail := func(err error) (CloseableRepository, error) {
		return nil, errors.System.Newf("cannot initizalize environment for flow %q: %w", flow.Name, err)
	}

	if flow.Environment.V == nil {
		return fail(errors.Config.Newf("no environment configured"))
	}

	factory, ok := configurationTypeToRepositoryFactory[reflect.TypeOf(flow.Environment.V)]
	if !ok {
		return fail(errors.Config.Newf("cannot handle environment type %v", reflect.TypeOf(flow.Environment.V)))
	}
	m := reflect.ValueOf(factory)
	rets := m.Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(flow.Name),
		reflect.ValueOf(flow.Environment.V),
		reflect.ValueOf(ap),
		reflect.ValueOf(i),
	})
	if err, ok := rets[1].Interface().(error); ok && err != nil {
		return fail(err)
	}
	return rets[0].Interface().(CloseableRepository), nil
}

var (
	configurationTypeToRepositoryFactory = make(map[reflect.Type]any)
)

type RepositoryFactory[C any, R CloseableRepository] func(context.Context, configuration.FlowName, C, alternatives.Provider, imp.Imp) (R, error)

func RegisterRepository[C any, R CloseableRepository](factory RepositoryFactory[C, R]) RepositoryFactory[C, R] {
	ct := reflect.TypeFor[C]()
	configurationTypeToRepositoryFactory[ct] = factory
	return factory
}

type repositoryDependenciesContextKey struct{}

type repositoryDependencies struct {
	hostKeys      []crypto.PrivateKey
	localAccounts *localAccountCoordinator
	management    ManagementCommandRunner
}

func repositoryDependenciesFrom(ctx context.Context) repositoryDependencies {
	result, _ := ctx.Value(repositoryDependenciesContextKey{}).(repositoryDependencies)
	return result
}

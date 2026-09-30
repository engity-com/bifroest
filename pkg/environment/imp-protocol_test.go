package environment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/engity-com/bifroest/pkg/alternatives"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	"github.com/engity-com/bifroest/pkg/imp"
	bkp "github.com/engity-com/bifroest/pkg/kubernetes"
	"github.com/engity-com/bifroest/pkg/session"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/template"
)

func TestParseImpProtocolRevision(t *testing.T) {
	for _, tc := range []struct {
		value   string
		present bool
		want    uint32
		bad     bool
	}{
		{want: 1},
		{value: "1", present: true, want: 1},
		{value: "2", present: true, want: 2},
		{value: "", present: true, bad: true},
		{value: "0", present: true, bad: true},
		{value: "-1", present: true, bad: true},
		{value: "garbage", present: true, bad: true},
		{value: "4294967296", present: true, bad: true},
	} {
		t.Run(fmt.Sprintf("%q/%v", tc.value, tc.present), func(t *testing.T) {
			metadata := map[string]string{}
			if tc.present {
				metadata[DockerLabelImpProtocolRevision] = tc.value
			}
			actual, err := parseImpProtocolRevision(metadata, DockerLabelImpProtocolRevision)
			if tc.bad {
				require.ErrorContains(t, err, "invalid IMP protocol revision")
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, actual)
			}
		})
	}
	require.False(t, impProtocolCompatible(1, executionLifecycleCapability))
	require.False(t, impProtocolCompatible(imp.ProtocolRevision, ""))
	require.True(t, impProtocolCompatible(imp.ProtocolRevision, executionLifecycleCapability))
}

type protocolDockerClient struct {
	client.APIClient
	containers []container.Summary
	listCalls  int
	removes    int
}

func (c *protocolDockerClient) ContainerList(_ context.Context, opts container.ListOptions) ([]container.Summary, error) {
	c.listCalls++
	if !slices.Contains(opts.Filters.Get("label"), DockerLabelFlow+"=test") || len(opts.Filters.Get("label")) != 2 {
		return nil, fmt.Errorf("missing flow/session Docker selectors: %v", opts.Filters)
	}
	var result []container.Summary
	for _, candidate := range c.containers {
		if candidate.Labels[DockerLabelFlow] == "test" && slices.Contains(opts.Filters.Get("label"), DockerLabelSessionId+"="+candidate.Labels[DockerLabelSessionId]) {
			result = append(result, candidate)
		}
	}
	return result, nil
}

func (c *protocolDockerClient) ContainerRemove(context.Context, string, container.RemoveOptions) error {
	c.removes++
	c.containers = nil
	return nil
}

type protocolKubernetesClient struct {
	bkp.Client
	clientSet kclient.Interface
}

func (c *protocolKubernetesClient) ClientSet() (kclient.Interface, error) { return c.clientSet, nil }
func (c *protocolKubernetesClient) Namespace() string                     { return "default" }

type protocolTestImp struct {
	imp.Imp
	key crypto.PublicKey
}

func (i *protocolTestImp) GetMasterPublicKey() (crypto.PublicKey, error) { return i.key, nil }

type protocolTestAlternatives struct{ alternatives.Provider }

func (*protocolTestAlternatives) FindOciImageFor(context.Context, sys.Os, sys.Arch) (string, error) {
	return "test/imp:latest", nil
}

func TestImpProtocolCompatibilityDocker(t *testing.T) {
	id := session.MustNewId()
	sess := &sshTestStoredSession{id: id}
	api := &protocolDockerClient{}
	repo := &DockerRepository{flow: "test", apiClient: api}
	facade := &RepositoryFacade{entries: map[configuration.FlowName]CloseableRepository{"test": repo}}
	check := func(compatible, found bool, revision uint32, dockerID string, bad bool) {
		t.Helper()
		actual, exists, rev, identity, err := facade.ImpProtocolCompatibility(t.Context(), sess)
		if bad {
			require.ErrorContains(t, err, "invalid IMP protocol revision")
		} else {
			require.NoError(t, err)
		}
		require.Equal(t, compatible, actual)
		require.Equal(t, found, exists)
		require.Equal(t, revision, rev)
		require.Equal(t, dockerID, identity.DockerID)
	}
	check(false, false, 0, "", false)
	api.containers = []container.Summary{{ID: "other", Labels: map[string]string{DockerLabelFlow: "foreign", DockerLabelSessionId: id.String()}}}
	check(false, false, 0, "", false)
	api.containers[0].Labels[DockerLabelFlow] = "test"
	api.containers[0].Labels[DockerLabelExecutionLifecycle] = executionLifecycleCapability
	check(false, true, 1, "other", false)
	_, err := repo.FindBySession(t.Context(), sess, nil)
	require.ErrorContains(t, err, "incompatible IMP protocol revision 1")
	require.Zero(t, api.removes)
	api.containers[0].Labels[DockerLabelImpProtocolRevision] = "2"
	check(true, true, 2, "other", false)
	delete(api.containers[0].Labels, DockerLabelExecutionLifecycle)
	check(false, true, 2, "other", false)
	_, err = repo.FindBySession(t.Context(), sess, nil)
	require.ErrorContains(t, err, "does not support execution lifecycle")
	api.containers[0].Labels[DockerLabelImpProtocolRevision] = "broken"
	check(false, true, 0, "other", true)
	_, err = repo.FindBySession(t.Context(), sess, nil)
	require.ErrorContains(t, err, "invalid IMP protocol revision")
	require.Zero(t, api.removes)
	api.containers[0].Labels[DockerLabelSessionId] = session.MustNewId().String()
	check(false, false, 0, "", false)
}

func TestImpProtocolCompatibilityRejectsDuplicateDockerResources(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	api := &protocolDockerClient{containers: []container.Summary{
		{ID: "old", Labels: map[string]string{DockerLabelFlow: "test", DockerLabelSessionId: sess.id.String()}},
		{ID: "new", Labels: map[string]string{DockerLabelFlow: "test", DockerLabelSessionId: sess.id.String(), DockerLabelImpProtocolRevision: "2", DockerLabelExecutionLifecycle: executionLifecycleCapability}},
	}}
	repo := &DockerRepository{flow: "test", apiClient: api}
	_, _, _, _, err := repo.ImpProtocolCompatibility(t.Context(), sess)
	require.ErrorContains(t, err, "multiple Docker containers")
	require.Zero(t, api.removes)
}

func TestExplicitDockerCleanupRemovesIncompatibleContainer(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	api := &protocolDockerClient{containers: []container.Summary{{ID: "old", Labels: map[string]string{
		DockerLabelFlow: "test", DockerLabelSessionId: sess.id.String(),
	}}}}
	repo := &DockerRepository{flow: "test", apiClient: api}
	_, err := repo.FindBySession(t.Context(), sess, &FindOpts{AutoCleanUpAllowed: common.P(true)})
	require.ErrorIs(t, err, ErrNoSuchEnvironment)
	require.Equal(t, 1, api.removes)
}

func TestDockerGuardedCleanupRejectsChangedMetadata(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	api := &protocolDockerClient{containers: []container.Summary{{ID: "same", Labels: map[string]string{
		DockerLabelFlow: "test", DockerLabelSessionId: sess.id.String(),
	}}}}
	repo := &DockerRepository{flow: "test", apiClient: api}
	_, _, _, identity, err := repo.ImpProtocolCompatibility(t.Context(), sess)
	require.NoError(t, err)
	api.containers[0].Labels[DockerLabelImpProtocolRevision] = "2"
	api.containers[0].Labels[DockerLabelExecutionLifecycle] = executionLifecycleCapability
	_, err = repo.FindBySession(t.Context(), sess, &FindOpts{AutoCleanUpAllowed: common.P(true), ExpectedResource: &identity})
	require.ErrorContains(t, err, "IMP protocol metadata changed")
	require.Zero(t, api.removes)
}

func TestDockerGuardedCleanupRejectsReplacedContainer(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached=%t", cached), func(t *testing.T) {
			sess := &sshTestStoredSession{id: session.MustNewId()}
			api := &protocolDockerClient{containers: []container.Summary{{ID: "old", Labels: map[string]string{
				DockerLabelFlow: "test", DockerLabelSessionId: sess.id.String(),
			}}}}
			repo := &DockerRepository{flow: "test", apiClient: api}
			_, found, _, identity, err := repo.ImpProtocolCompatibility(t.Context(), sess)
			require.NoError(t, err)
			require.True(t, found)
			if cached {
				instance := &docker{repository: repo, sessionId: sess.id, containerId: "old", protocolRevision: 1}
				instance.owners.Store(1)
				repo.activeInstances.Store(sess.id, instance)
			}
			api.containers[0].ID = "new"
			api.containers[0].Labels[DockerLabelImpProtocolRevision] = "2"
			api.containers[0].Labels[DockerLabelExecutionLifecycle] = executionLifecycleCapability

			type result struct{ err error }
			finished := make(chan result, 1)
			go func() {
				_, err := repo.FindBySession(t.Context(), sess, &FindOpts{AutoCleanUpAllowed: common.P(true), ExpectedResource: &identity})
				finished <- result{err}
			}()
			select {
			case result := <-finished:
				require.ErrorContains(t, result.err, "container identity changed")
				require.NotErrorIs(t, result.err, ErrNoSuchEnvironment)
			case <-time.After(2 * time.Second):
				t.Fatal("guarded Docker lookup deadlocked")
			}
			require.Zero(t, api.removes)
			require.Equal(t, "new", api.containers[0].ID)
		})
	}
}

func TestDockerGuardedCleanupRemovesSameContainer(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	api := &protocolDockerClient{containers: []container.Summary{{ID: "old", Labels: map[string]string{
		DockerLabelFlow: "test", DockerLabelSessionId: sess.id.String(),
	}}}}
	repo := &DockerRepository{flow: "test", apiClient: api}
	_, _, _, identity, err := repo.ImpProtocolCompatibility(t.Context(), sess)
	require.NoError(t, err)
	_, err = repo.FindBySession(t.Context(), sess, &FindOpts{AutoCleanUpAllowed: common.P(true), ExpectedResource: &identity})
	require.ErrorIs(t, err, ErrNoSuchEnvironment)
	require.Equal(t, 1, api.removes)
}

func TestDockerGuardedCleanupRejectsDifferentCachedContainer(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	api := &protocolDockerClient{containers: []container.Summary{{ID: "old", Labels: map[string]string{
		DockerLabelFlow: "test", DockerLabelSessionId: sess.id.String(),
	}}}}
	repo := &DockerRepository{flow: "test", apiClient: api}
	_, _, _, identity, err := repo.ImpProtocolCompatibility(t.Context(), sess)
	require.NoError(t, err)
	instance := &docker{repository: repo, sessionId: sess.id, containerId: "different", protocolRevision: 1}
	instance.owners.Store(1)
	repo.activeInstances.Store(sess.id, instance)
	_, err = repo.FindBySession(t.Context(), sess, &FindOpts{AutoCleanUpAllowed: common.P(true), ExpectedResource: &identity})
	require.ErrorContains(t, err, "cached container identity changed")
	require.NotErrorIs(t, err, ErrNoSuchEnvironment)
	require.Zero(t, api.removes)
	require.Equal(t, int32(1), instance.owners.Load())
}

func TestImpProtocolCompatibilityKubernetes(t *testing.T) {
	id := session.MustNewId()
	sess := &sshTestStoredSession{id: id}
	clientSet := fake.NewSimpleClientset()
	repo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: clientSet}, conf: &configuration.EnvironmentKubernetes{}}
	check := func(compatible, found bool, revision uint32, bad bool) {
		t.Helper()
		actual, exists, rev, identity, err := repo.ImpProtocolCompatibility(t.Context(), sess)
		if bad {
			require.ErrorContains(t, err, "invalid IMP protocol revision")
		} else {
			require.NoError(t, err)
		}
		require.Equal(t, compatible, actual)
		require.Equal(t, found, exists)
		require.Equal(t, revision, rev)
		if found {
			require.Equal(t, ResourceIdentity{KubernetesNamespace: "default", KubernetesName: "test", KubernetesUID: "original"}, identity)
		} else {
			require.Equal(t, ResourceIdentity{}, identity)
		}
	}
	check(false, false, 0, false)
	pod, err := clientSet.CoreV1().Pods("default").Create(t.Context(), &v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "test", Namespace: "default", UID: types.UID("original"), Labels: map[string]string{KubernetesLabelFlow: "foreign", KubernetesLabelSessionId: id.String()},
		Annotations: map[string]string{KubernetesAnnotationExecutionLifecycle: executionLifecycleCapability},
	}}, metav1.CreateOptions{})
	require.NoError(t, err)
	check(false, false, 0, false)
	pod.Labels[KubernetesLabelFlow] = "test"
	pod, err = clientSet.CoreV1().Pods("default").Update(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	check(false, true, 1, false)
	_, err = repo.FindBySession(t.Context(), sess, nil)
	require.ErrorContains(t, err, "incompatible IMP protocol revision 1")
	pod.Annotations[KubernetesAnnotationImpProtocolRevision] = "2"
	pod, err = clientSet.CoreV1().Pods("default").Update(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	check(true, true, 2, false)
	delete(pod.Annotations, KubernetesAnnotationExecutionLifecycle)
	pod, err = clientSet.CoreV1().Pods("default").Update(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	check(false, true, 2, false)
	_, err = repo.FindBySession(t.Context(), sess, nil)
	require.ErrorContains(t, err, "does not support execution lifecycle")
	pod.Annotations[KubernetesAnnotationImpProtocolRevision] = "broken"
	_, err = clientSet.CoreV1().Pods("default").Update(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	check(false, true, 0, true)
	_, err = repo.FindBySession(t.Context(), sess, nil)
	require.ErrorContains(t, err, "invalid IMP protocol revision")
	pod.Labels[KubernetesLabelSessionId] = session.MustNewId().String()
	_, err = clientSet.CoreV1().Pods("default").Update(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	check(false, false, 0, false)
}

func TestImpProtocolCompatibilityRejectsDuplicateKubernetesPods(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	labels := map[string]string{KubernetesLabelFlow: "test", KubernetesLabelSessionId: sess.id.String()}
	clientSet := fake.NewSimpleClientset(
		&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "default", UID: "old", Labels: labels}},
		&v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "new", Namespace: "default", UID: "new", Labels: labels,
			Annotations: map[string]string{KubernetesAnnotationImpProtocolRevision: "2", KubernetesAnnotationExecutionLifecycle: executionLifecycleCapability}}},
	)
	repo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: clientSet}, conf: &configuration.EnvironmentKubernetes{}}
	_, _, _, _, err := repo.ImpProtocolCompatibility(t.Context(), sess)
	require.ErrorContains(t, err, "multiple Kubernetes pods")
}

func TestExplicitKubernetesCleanupRemovesIncompatiblePod(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	clientSet := fake.NewSimpleClientset(&v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "old", Namespace: "default", Labels: map[string]string{
			KubernetesLabelFlow: "test", KubernetesLabelSessionId: sess.id.String(),
		},
	}})
	conf := &configuration.EnvironmentKubernetes{}
	conf.RemoveTimeout = time.Second
	repo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: clientSet}, conf: conf}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := repo.FindBySession(ctx, sess, &FindOpts{AutoCleanUpAllowed: common.P(true)})
	require.ErrorIs(t, err, ErrNoSuchEnvironment)
	_, err = clientSet.CoreV1().Pods("default").Get(t.Context(), "old", metav1.GetOptions{})
	require.Error(t, err)
}

func TestKubernetesGuardedCleanupRejectsReplacedPod(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached=%t", cached), func(t *testing.T) {
			sess := &sshTestStoredSession{id: session.MustNewId()}
			old := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default", UID: "old", Labels: map[string]string{
				KubernetesLabelFlow: "test", KubernetesLabelSessionId: sess.id.String(),
			}}}
			clientSet := fake.NewSimpleClientset(old)
			repo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: clientSet}, conf: &configuration.EnvironmentKubernetes{}}
			_, found, _, identity, err := repo.ImpProtocolCompatibility(t.Context(), sess)
			require.NoError(t, err)
			require.True(t, found)
			if cached {
				instance := &kubernetes{repository: repo, sessionId: sess.id, namespace: "default", name: "test", uid: "old", protocolRevision: 1}
				instance.owners.Store(1)
				repo.activeInstances.Store(sess.id, instance)
			}
			require.NoError(t, clientSet.CoreV1().Pods("default").Delete(t.Context(), "test", metav1.DeleteOptions{}))
			newPod := old.DeepCopy()
			newPod.UID = "new"
			newPod.Annotations = map[string]string{KubernetesAnnotationImpProtocolRevision: "2", KubernetesAnnotationExecutionLifecycle: executionLifecycleCapability}
			_, err = clientSet.CoreV1().Pods("default").Create(t.Context(), newPod, metav1.CreateOptions{})
			require.NoError(t, err)

			finished := make(chan error, 1)
			go func() {
				_, err := repo.FindBySession(t.Context(), sess, &FindOpts{AutoCleanUpAllowed: common.P(true), ExpectedResource: &identity})
				finished <- err
			}()
			select {
			case err := <-finished:
				require.ErrorContains(t, err, "pod identity changed")
				require.NotErrorIs(t, err, ErrNoSuchEnvironment)
			case <-time.After(2 * time.Second):
				t.Fatal("guarded Kubernetes lookup deadlocked")
			}
			stillThere, err := clientSet.CoreV1().Pods("default").Get(t.Context(), "test", metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, types.UID("new"), stillThere.UID)
		})
	}
}

func TestKubernetesGuardedCleanupRemovesSamePod(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	clientSet := fake.NewSimpleClientset(&v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "old", Namespace: "default", UID: "old", Labels: map[string]string{
			KubernetesLabelFlow: "test", KubernetesLabelSessionId: sess.id.String(),
		},
	}})
	conf := &configuration.EnvironmentKubernetes{RemoveTimeout: time.Second}
	repo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: clientSet}, conf: conf}
	_, _, _, identity, err := repo.ImpProtocolCompatibility(t.Context(), sess)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err = repo.FindBySession(ctx, sess, &FindOpts{AutoCleanUpAllowed: common.P(true), ExpectedResource: &identity})
	require.ErrorIs(t, err, ErrNoSuchEnvironment)
	_, err = clientSet.CoreV1().Pods("default").Get(t.Context(), "old", metav1.GetOptions{})
	require.Error(t, err)
}

func TestKubernetesGuardedCleanupRejectsChangedMetadata(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "same", Namespace: "default", UID: "stable", Labels: map[string]string{
		KubernetesLabelFlow: "test", KubernetesLabelSessionId: sess.id.String(),
	}}}
	clientSet := fake.NewSimpleClientset(pod)
	repo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: clientSet}, conf: &configuration.EnvironmentKubernetes{}}
	_, _, _, identity, err := repo.ImpProtocolCompatibility(t.Context(), sess)
	require.NoError(t, err)
	pod.Annotations = map[string]string{KubernetesAnnotationImpProtocolRevision: "2", KubernetesAnnotationExecutionLifecycle: executionLifecycleCapability}
	_, err = clientSet.CoreV1().Pods("default").Update(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	_, err = repo.FindBySession(t.Context(), sess, &FindOpts{AutoCleanUpAllowed: common.P(true), ExpectedResource: &identity})
	require.ErrorContains(t, err, "IMP protocol metadata changed")
	_, err = clientSet.CoreV1().Pods("default").Get(t.Context(), "same", metav1.GetOptions{})
	require.NoError(t, err)
}

func TestKubernetesGuardedCleanupRejectsDifferentCachedPod(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	clientSet := fake.NewSimpleClientset(&v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "test", Namespace: "default", UID: "old", Labels: map[string]string{
			KubernetesLabelFlow: "test", KubernetesLabelSessionId: sess.id.String(),
		},
	}})
	repo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: clientSet}, conf: &configuration.EnvironmentKubernetes{}}
	_, _, _, identity, err := repo.ImpProtocolCompatibility(t.Context(), sess)
	require.NoError(t, err)
	instance := &kubernetes{repository: repo, sessionId: sess.id, namespace: "default", name: "test", uid: "different", protocolRevision: 1}
	instance.owners.Store(1)
	repo.activeInstances.Store(sess.id, instance)
	_, err = repo.FindBySession(t.Context(), sess, &FindOpts{AutoCleanUpAllowed: common.P(true), ExpectedResource: &identity})
	require.ErrorContains(t, err, "cached pod identity changed")
	require.NotErrorIs(t, err, ErrNoSuchEnvironment)
	_, err = clientSet.CoreV1().Pods("default").Get(t.Context(), "test", metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, int32(1), instance.owners.Load())
}

func TestRemovePodDoesNotRemoveReplacedPod(t *testing.T) {
	clientSet := fake.NewSimpleClientset(&v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "replaced", Namespace: "default", UID: types.UID("new"),
	}})
	repo := &KubernetesRepository{client: &protocolKubernetesClient{clientSet: clientSet}, conf: &configuration.EnvironmentKubernetes{}}
	_, err := repo.removePod(t.Context(), "default", "replaced", nil, types.UID("old"))
	require.ErrorContains(t, err, "pod identity changed")
	_, err = clientSet.CoreV1().Pods("default").Get(t.Context(), "replaced", metav1.GetOptions{})
	require.NoError(t, err)
}

func TestRemovePodDoesNotRemovePodWithChangedProtocolMetadata(t *testing.T) {
	old := &v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "corrected", Namespace: "default", UID: "same", ResourceVersion: "1",
		Labels:      map[string]string{KubernetesLabelFlow: "test", KubernetesLabelSessionId: session.MustNewId().String()},
		Annotations: map[string]string{KubernetesAnnotationImpProtocolRevision: "1"},
	}}
	newPod := old.DeepCopy()
	newPod.ResourceVersion = "2"
	newPod.Annotations[KubernetesAnnotationImpProtocolRevision] = "2"
	newPod.Annotations[KubernetesAnnotationExecutionLifecycle] = executionLifecycleCapability
	clientSet := fake.NewSimpleClientset(newPod)
	repo := &KubernetesRepository{client: &protocolKubernetesClient{clientSet: clientSet}, conf: &configuration.EnvironmentKubernetes{}}
	_, err := repo.removePodChecked(t.Context(), "default", "corrected", nil, old, old.UID)
	require.ErrorContains(t, err, "IMP protocol metadata changed")
	_, err = clientSet.CoreV1().Pods("default").Get(t.Context(), "corrected", metav1.GetOptions{})
	require.NoError(t, err)
}

func TestCachedKubernetesPodRejectsChangedAnnotations(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "test", Namespace: "default",
		Labels:      map[string]string{KubernetesLabelFlow: "test", KubernetesLabelSessionId: sess.id.String()},
		Annotations: map[string]string{KubernetesAnnotationExecutionLifecycle: executionLifecycleCapability, KubernetesAnnotationImpProtocolRevision: "2"},
	}}
	clientSet := fake.NewSimpleClientset(pod)
	repo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: clientSet}, conf: &configuration.EnvironmentKubernetes{}}
	instance := &kubernetes{repository: repo, sessionId: sess.id, name: pod.Name, namespace: pod.Namespace, uid: pod.UID, protocolRevision: imp.ProtocolRevision, executionLifecycle: executionLifecycleCapability}
	instance.owners.Store(1)
	repo.activeInstances.Store(sess.id, instance)
	pod.Annotations[KubernetesAnnotationImpProtocolRevision] = "1"
	_, err := clientSet.CoreV1().Pods("default").Update(t.Context(), pod, metav1.UpdateOptions{})
	require.NoError(t, err)
	value, err := repo.FindBySession(t.Context(), sess, nil)
	require.Nil(t, value)
	require.ErrorContains(t, err, "incompatible IMP protocol revision 1")
	require.Equal(t, int32(1), instance.owners.Load())
}

func TestCachedKubernetesPodRefetchesOnUIDChange(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "test", Namespace: "default", UID: "new",
		Labels:      map[string]string{KubernetesLabelFlow: "test", KubernetesLabelSessionId: sess.id.String()},
		Annotations: map[string]string{KubernetesAnnotationImpProtocolRevision: "2", KubernetesAnnotationExecutionLifecycle: executionLifecycleCapability},
	}, Status: v1.PodStatus{Phase: v1.PodRunning}}
	clientSet := fake.NewSimpleClientset(pod)
	repo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: clientSet}, conf: &configuration.EnvironmentKubernetes{}}
	instance := &kubernetes{repository: repo, sessionId: sess.id, name: pod.Name, namespace: pod.Namespace, uid: "old", protocolRevision: imp.ProtocolRevision, executionLifecycle: executionLifecycleCapability}
	instance.owners.Store(1)
	repo.activeInstances.Store(sess.id, instance)

	value, err := repo.FindBySession(t.Context(), sess, nil)
	require.Nil(t, value)
	require.ErrorContains(t, err, "missing annotation "+KubernetesAnnotationCreatedRemoteHost)
	_, cached := repo.activeInstances.Load(sess.id)
	require.False(t, cached)
	require.Equal(t, int32(1), instance.owners.Load())
}

func TestKubernetesParsePodStoresUID(t *testing.T) {
	id := session.MustNewId()
	instance := &kubernetes{repository: &KubernetesRepository{flow: "test"}}
	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "test", Namespace: "default", UID: "pod-uid",
		Labels: map[string]string{KubernetesLabelFlow: "test", KubernetesLabelSessionId: id.String()},
		Annotations: map[string]string{
			KubernetesAnnotationImpProtocolRevision: "2", KubernetesAnnotationExecutionLifecycle: executionLifecycleCapability,
			KubernetesAnnotationCreatedRemoteHost: "127.0.0.1", KubernetesAnnotationShellCommand: `["sh"]`, KubernetesAnnotationExecCommand: `["sh"]`,
		},
	}}
	require.NoError(t, instance.parsePod(pod))
	require.Equal(t, pod.UID, instance.uid)
}

func TestImpProtocolCachedEnvironmentsRejectStaleRevisions(t *testing.T) {
	sess := &sshTestStoredSession{id: session.MustNewId()}
	dockerRepo := &DockerRepository{flow: "test"}
	cachedDocker := &docker{repository: dockerRepo, sessionId: sess.id, containerId: "cached", protocolRevision: 1, executionLifecycle: executionLifecycleCapability}
	cachedDocker.owners.Store(1)
	dockerRepo.activeInstances.Store(sess.id, cachedDocker)
	value, err := dockerRepo.FindBySession(t.Context(), sess, nil)
	require.Nil(t, value)
	require.ErrorContains(t, err, "incompatible IMP protocol revision 1")
	require.Equal(t, int32(1), cachedDocker.owners.Load())

	pod := &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "cached", Namespace: "default", Labels: map[string]string{KubernetesLabelFlow: "test", KubernetesLabelSessionId: sess.id.String()}}}
	kubeRepo := &KubernetesRepository{flow: "test", client: &protocolKubernetesClient{clientSet: fake.NewSimpleClientset(pod)}, conf: &configuration.EnvironmentKubernetes{}}
	cachedPod := &kubernetes{repository: kubeRepo, sessionId: sess.id, name: "cached", namespace: "default", protocolRevision: imp.ProtocolRevision}
	cachedPod.owners.Store(1)
	kubeRepo.activeInstances.Store(sess.id, cachedPod)
	value, err = kubeRepo.FindBySession(t.Context(), sess, nil)
	require.Nil(t, value)
	require.ErrorContains(t, err, "does not support execution lifecycle")
	require.Equal(t, int32(1), cachedPod.owners.Load())
}

func TestImpProtocolProvisioningMetadata(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	key, err := crypto.PublicKeyFromSdk(public)
	require.NoError(t, err)
	i := &protocolTestImp{key: key}
	ctx, cancel := newSshTestContext()
	defer cancel()
	sess := &sshTestStoredSession{id: session.MustNewId()}
	req := &sshTestTask{context: ctx, connection: &sshTestConnection{context: ctx}, authorization: &sshTestAuthorization{session: sess}}

	dockerConf := &configuration.EnvironmentDocker{}
	require.NoError(t, dockerConf.SetDefaults())
	dockerRepo := &DockerRepository{flow: "test", conf: dockerConf, imp: i, hostOs: sys.OsLinux}
	containerConfig, err := dockerRepo.resolveContainerConfig(req, sess)
	require.NoError(t, err)
	require.Equal(t, "2", containerConfig.Labels[DockerLabelImpProtocolRevision])
	require.Equal(t, executionLifecycleCapability, containerConfig.Labels[DockerLabelExecutionLifecycle])

	kubeConf := &configuration.EnvironmentKubernetes{Os: sys.OsLinux}
	require.NoError(t, kubeConf.SetDefaults())
	kubeConf.Name = template.MustNewString("test-pod")
	clientSet := fake.NewSimpleClientset()
	kubeRepo := &KubernetesRepository{flow: "test", conf: kubeConf, client: &protocolKubernetesClient{clientSet: clientSet}, alternatives: &protocolTestAlternatives{}, imp: i}
	pod, _, err := kubeRepo.resolvePodConfig(req, sess)
	require.NoError(t, err)
	require.Equal(t, "2", pod.Annotations[KubernetesAnnotationImpProtocolRevision])
	require.Equal(t, executionLifecycleCapability, pod.Annotations[KubernetesAnnotationExecutionLifecycle])
}

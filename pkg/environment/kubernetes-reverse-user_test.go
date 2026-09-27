package environment

import (
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/imp"
	"github.com/engity-com/bifroest/pkg/session"
)

func TestKubernetesRejectsChangedReverseTCPIdentity(t *testing.T) {
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test", Namespace: "default",
			Labels: map[string]string{
				KubernetesLabelFlow:      "test",
				KubernetesLabelSessionId: session.MustNewId().String(),
			},
			Annotations: map[string]string{
				KubernetesAnnotationCreatedRemoteHost: "127.0.0.1",
				KubernetesAnnotationShellCommand:      `["sh"]`,
				KubernetesAnnotationExecCommand:       `["sh"]`,
			},
		},
		Spec: v1.PodSpec{
			OS: &v1.PodOS{Name: v1.Linux},
			Containers: []v1.Container{{
				Name:            "bifroest",
				SecurityContext: &v1.SecurityContext{RunAsUser: common.P[int64](0)},
				Env:             []v1.EnvVar{{Name: imp.EnvVarReverseTCPUser, Value: "0"}},
			}},
		},
	}
	for _, tc := range []struct {
		name   string
		change func(*v1.Pod)
		valid  bool
	}{
		{"root default", func(*v1.Pod) {}, true},
		{"admission changes UID", func(p *v1.Pod) { p.Spec.Containers[0].SecurityContext.RunAsUser = common.P[int64](10001) }, false},
		{"annotation changes user", func(p *v1.Pod) { p.Annotations[KubernetesAnnotationUser] = "10001" }, false},
		{"nonroot user pinned", func(p *v1.Pod) {
			p.Annotations[KubernetesAnnotationUser] = "10001"
			p.Spec.Containers[0].Env[0].Value = "10001"
		}, true},
		{"duplicate pin", func(p *v1.Pod) {
			p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, v1.EnvVar{Name: imp.EnvVarReverseTCPUser, Value: "0"})
		}, false},
		{"legacy pod without pin", func(p *v1.Pod) { p.Spec.Containers[0].Env = nil }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := pod.DeepCopy()
			tc.change(current)
			env := &kubernetes{repository: &KubernetesRepository{flow: configuration.FlowName("test")}}
			err := env.parsePod(current)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "target user annotation does not match pinned IMP user")
			}
		})
	}
}

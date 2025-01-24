package kubernetes

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
)

func Test_Kubeconfig_GetClient_emptyAndNoDefault_fails(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/does_not_exist.yml"

	actual, actualErr := instance.GetClient("", "")
	require.ErrorContains(t, actualErr, `neither does the default kubeconfig "resources/does_not_exist.yml" exists nor was a `)
	require.Nil(t, actual)
}

func Test_Kubeconfig_GetClient_twoContexts_succeeds(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	instance := Kubeconfig{plain: []byte("resources/kubeconfig_two_contexts.yml")}
	instance.overwrites.defaultFile = "resources/does_not_exist.yml"

	actual, actualErr := instance.getClient("", "")
	require.NoError(t, actualErr)
	require.NotNil(t, actual)
	require.Equal(t, "http://127.0.0.1:8080", actual.restConfig.Host)
	require.Equal(t, "context1", actual.contextName)
	require.Equal(t, "", actual.namespace)
}

func Test_Kubeconfig_GetClient_emptyTwoContexts_specificContext_succeeds(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/kubeconfig_two_contexts.yml"

	actual, actualErr := instance.getClient("context2", "")
	require.NoError(t, actualErr)
	require.NotNil(t, actual)
	require.Equal(t, "http://127.0.0.2:8080", actual.restConfig.Host)
	require.Equal(t, "context2", actual.contextName)
	require.Equal(t, "", actual.namespace)
}

func Test_Kubeconfig_GetClient_emptyAndEnvVarSet_succeeds(t *testing.T) {
	defer setEnvVarTemporaryToFileContent(t, EnvVarKubeconfig, "resources/kubeconfig_alternative.yml")()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/kubeconfig_two_contexts.yml"

	actual, actualErr := instance.getClient("", "")
	require.NoError(t, actualErr)
	require.NotNil(t, actual)
	require.Equal(t, "http://127.0.0.3:8080", actual.restConfig.Host)
	require.Equal(t, "context3", actual.contextName)
	require.Equal(t, "", actual.namespace)
}

func Test_Kubeconfig_GetClient_emptyAndEnvVarFilesSet_succeeds(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer setEnvVarTemporaryTo(EnvVarKubeconfigFiles, "resources/kubeconfig_alternative.yml")()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/non_existent.yml"

	actual, actualErr := instance.getClient("", "")
	require.NoError(t, actualErr)
	require.NotNil(t, actual)
	require.Equal(t, "http://127.0.0.3:8080", actual.restConfig.Host)
	require.Equal(t, "context3", actual.contextName)
	require.Equal(t, "", actual.namespace)
}

func Test_Kubeconfig_GetClient_emptyAndEnvVarMultiFilesSet_succeeds(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer setEnvVarTemporaryTo(EnvVarKubeconfigFiles, fmt.Sprintf("resources/kubeconfig_two_contexts.yml%cresources/kubeconfig_alternative.yml", filepath.ListSeparator))()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/non_existent.yml"

	actual, actualErr := instance.getClient("", "")
	require.NoError(t, actualErr)
	require.NotNil(t, actual)
	require.Equal(t, "http://127.0.0.1:8080", actual.restConfig.Host)
	require.Equal(t, "context1", actual.contextName)
	require.Equal(t, "", actual.namespace)
}

func Test_Kubeconfig_GetClient_emptyAndEnvVarMultiFilesSetAndExplicitContext_succeeds(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer setEnvVarTemporaryTo(EnvVarKubeconfigFiles, fmt.Sprintf("resources/kubeconfig_two_contexts.yml%cresources/kubeconfig_alternative.yml", filepath.ListSeparator))()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/non_existent.yml"

	actual, actualErr := instance.getClient("context3", "")
	require.NoError(t, actualErr)
	require.NotNil(t, actual)
	require.Equal(t, "http://127.0.0.3:8080", actual.restConfig.Host)
	require.Equal(t, "context3", actual.contextName)
	require.Equal(t, "", actual.namespace)
}

func Test_Kubeconfig_GetClient_emptyAndAllEnvVarsSet_succeeds(t *testing.T) {
	defer setEnvVarTemporaryToFileContent(t, EnvVarKubeconfig, "resources/kubeconfig_alternative.yml")()
	defer setEnvVarTemporaryTo(EnvVarKubeconfigFiles, "resources/kubeconfig_two_contexts.yml")()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/non_existent.yml"

	actual, actualErr := instance.getClient("", "")
	require.NoError(t, actualErr)
	require.NotNil(t, actual)
	require.Equal(t, "http://127.0.0.3:8080", actual.restConfig.Host)
	require.Equal(t, "context3", actual.contextName)
	require.Equal(t, "", actual.namespace)
}

func Test_Kubeconfig_GetClient_emptyAndTwoContexts_withoutCurrentContext_fails(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/kubeconfig_without_current_context.yml"

	actual, actualErr := instance.getClient("", "")
	require.Equal(t, clientcmd.ErrNoContext, actualErr)
	require.Nil(t, actual)
}

func Test_Kubeconfig_GetClient_emptyTwoContexts_specificNonExistingContext_fails(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/kubeconfig_two_contexts.yml"

	actual, actualErr := instance.getClient("wrong", "")
	require.ErrorContains(t, actualErr, `kubeconfig does not contain context "wrong"`)
	require.Nil(t, actual)
}

func Test_Kubeconfig_GetClient_doesNotExist_fails(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	instance := Kubeconfig{plain: []byte("fooo")}

	actual, actualErr := instance.getClient("wrong", "")
	require.ErrorContains(t, actualErr, "open fooo: ")
	require.Nil(t, actual)
}

func Test_Kubeconfig_GetClient_emptyIncluster_succeeds(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_HOST", "127.0.0.66")()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_PORT", "8081")()
	instance := Kubeconfig{}
	instance.overwrites.defaultFile = "resources/non_existent"
	instance.overwrites.serviceTokenFile = "resources/serviceaccount_token"
	instance.overwrites.serviceRootCaFile = "resources/serviceaccount_ca.crt"
	instance.overwrites.serviceNamespaceFile = "resources/serviceaccount_namespace"

	actual, actualErr := instance.getClient("", "")
	require.NoError(t, actualErr)
	require.NotNil(t, actual)
	require.Equal(t, "https://127.0.0.66:8081", actual.restConfig.Host)
	require.Equal(t, KubeconfigInCluster, actual.contextName)
	require.Equal(t, "aNamespace", actual.namespace)
}

func Test_Kubeconfig_GetClient_incluster_succeeds(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_HOST", "127.0.0.66")()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_PORT", "8081")()
	instance := Kubeconfig{plain: []byte(KubeconfigInCluster)}
	instance.overwrites.serviceTokenFile = "resources/serviceaccount_token"
	instance.overwrites.serviceRootCaFile = "resources/serviceaccount_ca.crt"
	instance.overwrites.serviceNamespaceFile = "resources/serviceaccount_namespace"

	actual, actualErr := instance.getClient("", "")
	require.NoError(t, actualErr)
	require.NotNil(t, actual)
	require.Equal(t, "https://127.0.0.66:8081", actual.restConfig.Host)
	require.Equal(t, KubeconfigInCluster, actual.contextName)
	require.Equal(t, "aNamespace", actual.namespace)
}

func Test_Kubeconfig_GetClient_incluster_withoutServiceHost_fails(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	defer unsetEnvVarTemporary("KUBERNETES_SERVICE_HOST")()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_PORT", "8081")()
	instance := Kubeconfig{plain: []byte(KubeconfigInCluster)}
	instance.overwrites.serviceTokenFile = "resources/serviceaccount_token"
	instance.overwrites.serviceRootCaFile = "resources/serviceaccount_ca.crt"
	instance.overwrites.serviceNamespaceFile = "resources/serviceaccount_namespace"

	actual, actualErr := instance.getClient("unable to load in-cluster configuration, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be defined", "")
	require.ErrorContains(t, actualErr, "")
	require.Nil(t, actual)
}

func Test_Kubeconfig_GetClient_incluster_withoutServicePort_fails(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_HOST", "127.0.0.66")()
	defer unsetEnvVarTemporary("KUBERNETES_SERVICE_PORT")()
	instance := Kubeconfig{plain: []byte(KubeconfigInCluster)}
	instance.overwrites.serviceTokenFile = "resources/serviceaccount_token"
	instance.overwrites.serviceRootCaFile = "resources/serviceaccount_ca.crt"
	instance.overwrites.serviceNamespaceFile = "resources/serviceaccount_namespace"

	actual, actualErr := instance.getClient("unable to load in-cluster configuration, KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be defined", "")
	require.ErrorContains(t, actualErr, "")
	require.Nil(t, actual)
}

func Test_Kubeconfig_GetClient_incluster_withoutTokenFile_fails(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_HOST", "127.0.0.66")()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_PORT", "8081")()
	instance := Kubeconfig{plain: []byte(KubeconfigInCluster)}
	instance.overwrites.serviceTokenFile = "resources/serviceaccount_token_non_existing"
	instance.overwrites.serviceRootCaFile = "resources/serviceaccount_ca.crt"
	instance.overwrites.serviceNamespaceFile = "resources/serviceaccount_namespace"

	actual, actualErr := instance.getClient("", "")
	require.ErrorContains(t, actualErr, `can't read token file "resources/serviceaccount_token_non_existing"`)
	require.Nil(t, actual)
}

func Test_Kubeconfig_GetClient_incluster_withoutRootCaFile_fails(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_HOST", "127.0.0.66")()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_PORT", "8081")()
	instance := Kubeconfig{plain: []byte(KubeconfigInCluster)}
	instance.overwrites.serviceTokenFile = "resources/serviceaccount_token"
	instance.overwrites.serviceRootCaFile = "resources/serviceaccount_ca.crt_non_existing"
	instance.overwrites.serviceNamespaceFile = "resources/serviceaccount_namespace"

	actual, actualErr := instance.getClient("", "")
	require.ErrorContains(t, actualErr, `can't read root CA file "resources/serviceaccount_ca.crt_non_existing"`)
	require.Nil(t, actual)
}

func Test_Kubeconfig_GetClient_incluster_withoutNamespaceFail_fails(t *testing.T) {
	defer unsetEnvVarTemporary(EnvVarKubeconfig)()
	defer unsetEnvVarTemporary(EnvVarKubeconfigFiles)()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_HOST", "127.0.0.66")()
	defer setEnvVarTemporaryTo("KUBERNETES_SERVICE_PORT", "8081")()
	instance := Kubeconfig{plain: []byte(KubeconfigInCluster)}
	instance.overwrites.serviceTokenFile = "resources/serviceaccount_token"
	instance.overwrites.serviceRootCaFile = "resources/serviceaccount_ca.crt"
	instance.overwrites.serviceNamespaceFile = "resources/serviceaccount_namespace_non_existing"

	actual, actualErr := instance.getClient("", "")
	require.ErrorContains(t, actualErr, `can't read namespace file "resources/serviceaccount_namespace_non_existing"`)
	require.Nil(t, actual)
}

func setEnvVarTemporaryTo(key, value string) (rollback envVarRollback) {
	if oldValue, oldContentExists := os.LookupEnv(key); oldContentExists {
		rollback = func() {
			_ = os.Setenv(key, oldValue)
		}
	} else {
		rollback = func() {
			_ = os.Unsetenv(key)
		}
	}
	_ = os.Setenv(key, value)
	return
}

func unsetEnvVarTemporary(key string) (rollback envVarRollback) {
	if oldValue, oldContentExists := os.LookupEnv(key); oldContentExists {
		rollback = func() {
			_ = os.Setenv(key, oldValue)
		}
	} else {
		rollback = func() {
			_ = os.Unsetenv(key)
		}
	}
	_ = os.Unsetenv(key)
	return
}

func setEnvVarTemporaryToFileContent(t testing.TB, key, filename string) (rollback envVarRollback) {
	value, err := os.ReadFile(filename)
	if err != nil {
		t.Errorf("cannot set contents of %s to environment %s", filename, key)
		t.Fail()
		return
	}

	return setEnvVarTemporaryTo(key, string(value))
}

type envVarRollback func()

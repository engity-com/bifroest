package environment

import (
	"net/http"
	"path/filepath"

	"github.com/docker/docker/client"
	"github.com/docker/go-connections/sockets"
	"github.com/docker/go-connections/tlsconfig"

	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

type dockerConnectionReference struct {
	host       string
	apiVersion string
	certPath   string
	tlsVerify  bool
}

func (this *DockerRepository) newApiClientFor(sess session.Session) (_ client.APIClient, _ error) {
	fail := func(err error) (client.APIClient, error) {
		return nil, err
	}

	ref, err := this.newConnectionReference(sess)
	if err != nil {
		return fail(err)
	}
	apiClient, err := ref.toApiClient()
	if err != nil {
		return fail(err)
	}

	return apiClient, nil
}

func (this *DockerRepository) newConnectionReference(sess session.Session) (_ *dockerConnectionReference, err error) {
	fail := func(err error) (*dockerConnectionReference, error) {
		return nil, err
	}
	failf := func(msg string, args ...any) (*dockerConnectionReference, error) {
		return fail(errors.Config.Newf(msg, args...))
	}
	var result dockerConnectionReference

	if result.host, err = this.conf.Host.Render(sess); err != nil {
		return failf("cannot evaluate host: %w", err)
	}
	if result.apiVersion, err = this.conf.ApiVersion.Render(sess); err != nil {
		return failf("cannot evaluate apiVersion: %w", err)
	}
	if result.certPath, err = this.conf.CertPath.Render(sess); err != nil {
		return failf("cannot evaluate certPath: %w", err)
	}
	if result.tlsVerify, err = this.conf.TlsVerify.Render(sess); err != nil {
		return failf("cannot evaluate tlsVerify: %w", err)
	}
	return &result, nil
}

func (this dockerConnectionReference) toApiClient() (_ *client.Client, err error) {
	fail := func(err error) (*client.Client, error) {
		return nil, err
	}

	hostURL, err := client.ParseHostURL(client.DefaultDockerHost)
	if err != nil {
		return fail(err)
	}

	httpTransport := http.Transport{}
	if err := sockets.ConfigureTransport(&httpTransport, hostURL.Scheme, hostURL.Host); err != nil {
		return fail(err)
	}
	httpClient := http.Client{
		Transport:     &httpTransport,
		CheckRedirect: client.CheckRedirect,
	}

	clientOpts := []client.Opt{client.WithHTTPClient(&httpClient)}
	if v := this.host; v != "" {
		clientOpts = append(clientOpts, client.WithHost(v))
	}
	if v := this.apiVersion; v != "" {
		clientOpts = append(clientOpts, client.WithVersion(v))
	}
	if v := this.certPath; v != "" {
		if httpTransport.TLSClientConfig, err = tlsconfig.Client(tlsconfig.Options{
			CAFile:             filepath.Join(v, "ca.pem"),
			CertFile:           filepath.Join(v, "cert.pem"),
			KeyFile:            filepath.Join(v, "key.pem"),
			InsecureSkipVerify: !this.tlsVerify,
		}); err != nil {
			return fail(err)
		}
	}

	apiClient, err := client.NewClientWithOpts(clientOpts...)
	if err != nil {
		return fail(err)
	}

	return apiClient, nil
}

package service

import (
	"encoding/base64"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/authorization"
	"github.com/engity-com/bifroest/pkg/browserkey"
)

var errWebKeyProof = browserkey.ErrProof

func parseWebPublicKey(value string) (ssh.PublicKey, error) {
	return browserkey.ParsePublicKey(value)
}

func webKeyChallenge(conn *webLoginConnection, key ssh.PublicKey, expires time.Time) ([]byte, error) {
	return browserkey.NewChallenge(browserkey.Scope{Origin: conn.scope.Origin, Slug: conn.scope.Slug, User: conn.remote.user}, conn.Id().String(), key, expires)
}

func verifyWebKeyProof(key ssh.PublicKey, challenge []byte, encoded string) error {
	return browserkey.Verify(key, challenge, encoded)
}

func (this *webService) authorizeWebKey(attempt *webLoginAttempt, key ssh.PublicKey) (authorization.Authorization, error) {
	challenge, err := webKeyChallenge(attempt.conn, key, attempt.expires)
	if err != nil {
		return nil, err
	}
	encoded, err := attempt.exchange(webLoginStep{Kind: "public-key", Challenge: base64.StdEncoding.EncodeToString(challenge)})
	if err != nil {
		return nil, err
	}
	if err := verifyWebKeyProof(key, challenge, encoded); err != nil {
		return nil, err
	}
	if err := attempt.conn.Lifetime().Err(); err != nil {
		return nil, err
	}
	return this.service.authorizer.AuthorizePublicKey(&publicKeyAuthorizeRequest{authorizeRequest: authorizeRequest{service: this.service, connection: attempt.conn}, publicKey: key, verified: true})
}

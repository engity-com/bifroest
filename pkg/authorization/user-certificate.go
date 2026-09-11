package authorization

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto"
	bnet "github.com/engity-com/bifroest/pkg/net"
)

type userCertificateAuthorizer interface {
	SupportsUserCertificates()
}

type authorizedKeySource func(func(ssh.PublicKey, []crypto.AuthorizedKeyOption) (bool, error)) error

func loadTrustedUserCAs(conf *configuration.UserCertificateAuthorityProperties) ([]ssh.PublicKey, error) {
	inline, err := conf.TrustedUserCAs.Get()
	if err != nil {
		return nil, fmt.Errorf("cannot load trustedUserCAs: %w", err)
	}
	if !conf.TrustedUserCAs.IsZero() && len(inline) == 0 {
		return nil, fmt.Errorf("trustedUserCAs does not contain a public key")
	}
	fromFile, err := conf.TrustedUserCAsFile.Get()
	if err != nil {
		return nil, fmt.Errorf("cannot load trustedUserCAsFile: %w", err)
	}
	if !conf.TrustedUserCAsFile.IsZero() && len(fromFile) == 0 {
		return nil, fmt.Errorf("trustedUserCAsFile does not contain a public key")
	}
	return append(inline, fromFile...), nil
}

func evaluatePublicKeyCredential(remote ssh.PublicKey, username string, remoteHost bnet.Host, trustedUserCAs []ssh.PublicKey, source authorizedKeySource, now time.Time) (*AuthorizedKeyPolicy, bool, error) {
	certificate, isCertificate := remote.(*ssh.Certificate)
	if isCertificate {
		for _, ca := range trustedUserCAs {
			if publicKeysEqual(certificate.SignatureKey, ca) && checkUserCertificate(certificate, username, nil, now) {
				policy, err := authorizedKeyPolicyForCertificate(nil, certificate)
				if err != nil {
					return nil, false, nil
				}
				return policy, true, nil
			}
		}
	}

	var result *AuthorizedKeyPolicy
	accepted := false
	err := source(func(candidate ssh.PublicKey, options []crypto.AuthorizedKeyOption) (bool, error) {
		if isCertificate {
			if !publicKeysEqual(certificate.SignatureKey, candidate) {
				return true, nil
			}
			certificateAuthority, principals, remaining, err := splitCertificateAuthorityOptions(options)
			if err != nil {
				return false, err
			}
			if !certificateAuthority {
				return true, nil
			}
			if !checkUserCertificate(certificate, username, principals, now) {
				return true, nil
			}
			base, permitted, err := evaluateAuthorizedKeyOptions(remaining, remoteHost, now)
			if err != nil {
				return false, err
			}
			if !permitted {
				return true, nil
			}
			result, err = authorizedKeyPolicyForCertificate(base, certificate)
			if err != nil {
				return true, nil
			}
			accepted = true
			return false, nil
		}

		if !publicKeysEqual(remote, candidate) {
			return true, nil
		}
		certificateAuthority, _, remaining, err := splitCertificateAuthorityOptions(options)
		if err != nil {
			return false, err
		}
		if certificateAuthority {
			return true, nil
		}
		result, accepted, err = evaluateAuthorizedKeyOptions(remaining, remoteHost, now)
		if err != nil {
			return false, err
		}
		if !accepted {
			return true, nil
		}
		return false, nil
	})
	return result, accepted, err
}

func splitCertificateAuthorityOptions(options []crypto.AuthorizedKeyOption) (certificateAuthority bool, principals []string, remaining []crypto.AuthorizedKeyOption, err error) {
	for _, option := range options {
		switch option.Type {
		case crypto.AuthorizedKeyCertAuthority:
			if certificateAuthority {
				return false, nil, nil, fmt.Errorf("authorized key option %q is configured more than once", option.Type)
			}
			certificateAuthority = true
		case crypto.AuthorizedKeyPrincipals:
			if principals != nil {
				return false, nil, nil, fmt.Errorf("authorized key option %q is configured more than once", option.Type)
			}
			for _, principal := range strings.Split(option.Value, ",") {
				principal = strings.TrimSpace(principal)
				if principal == "" {
					return false, nil, nil, fmt.Errorf("illegal empty authorized key principal")
				}
				principals = append(principals, principal)
			}
		default:
			remaining = append(remaining, option)
		}
	}
	if principals != nil && !certificateAuthority {
		return false, nil, nil, fmt.Errorf("authorized key option %q requires %q", crypto.AuthorizedKeyPrincipals, crypto.AuthorizedKeyCertAuthority)
	}
	return certificateAuthority, principals, remaining, nil
}

func checkUserCertificate(certificate *ssh.Certificate, username string, allowedPrincipals []string, now time.Time) bool {
	return checkUserCertificateWithCriticalOptions(certificate, username, allowedPrincipals, nil, now)
}

func checkUserCertificateWithCriticalOptions(certificate *ssh.Certificate, username string, allowedPrincipals, supportedCriticalOptions []string, now time.Time) bool {
	if certificate == nil || certificate.CertType != ssh.UserCert || username == "" || len(certificate.ValidPrincipals) == 0 {
		return false
	}
	if !containsString(certificate.ValidPrincipals, username) {
		return false
	}
	if len(allowedPrincipals) > 0 {
		matched := false
		for _, principal := range allowedPrincipals {
			if containsString(certificate.ValidPrincipals, principal) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	checker := ssh.CertChecker{
		SupportedCriticalOptions: supportedCriticalOptions,
		Clock:                    func() time.Time { return now },
	}
	return checker.CheckCert(username, certificate) == nil
}

func evaluateBifroestUserCertificate(remote ssh.PublicKey, username string, trustedUserCAs []ssh.PublicKey, audiences []string, maxValidity time.Duration, now time.Time) (*AuthorizationEvidence, *AuthorizedKeyPolicy, bool, error) {
	certificate, ok := remote.(*ssh.Certificate)
	if !ok {
		return nil, nil, false, nil
	}
	marker, exists := certificate.CriticalOptions[BifroestDelegationCriticalOption]
	if !exists || marker != "" || len(certificate.CriticalOptions) != 1 {
		return nil, nil, false, nil
	}
	trusted := false
	for _, ca := range trustedUserCAs {
		if publicKeysEqual(certificate.SignatureKey, ca) {
			trusted = true
			break
		}
	}
	if !trusted || !checkUserCertificateWithCriticalOptions(certificate, username, nil, []string{BifroestDelegationCriticalOption}, now) {
		return nil, nil, false, nil
	}
	raw, exists := certificate.Extensions[AuthorizationEvidenceExtension]
	if !exists {
		return nil, nil, false, nil
	}
	evidence, err := DecodeAuthorizationEvidence([]byte(raw))
	if err != nil {
		return nil, nil, false, err
	}
	policy, err := ValidateBifroestDelegationEvidence(evidence, certificate, username, audiences, maxValidity, now)
	if err != nil {
		return nil, nil, false, err
	}
	return evidence, policy, true, nil
}

func authorizedKeyPolicyForCertificate(base *AuthorizedKeyPolicy, certificate *ssh.Certificate) (*AuthorizedKeyPolicy, error) {
	for name, value := range certificate.Extensions {
		switch name {
		case "permit-pty", "permit-port-forwarding", "permit-agent-forwarding":
			if value != "" {
				return nil, fmt.Errorf("certificate extension %q must not have a value", name)
			}
		}
	}
	if base == nil {
		base = &AuthorizedKeyPolicy{
			PtyAllowed:             true,
			PortForwardingAllowed:  true,
			AgentForwardingAllowed: true,
		}
	}
	base.PtyAllowed = base.PtyAllowed && hasCertificateExtension(certificate, "permit-pty")
	base.PortForwardingAllowed = base.PortForwardingAllowed && hasCertificateExtension(certificate, "permit-port-forwarding")
	base.AgentForwardingAllowed = base.AgentForwardingAllowed && hasCertificateExtension(certificate, "permit-agent-forwarding")
	return base, nil
}

func hasCertificateExtension(certificate *ssh.Certificate, name string) bool {
	_, ok := certificate.Extensions[name]
	return ok
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func publicKeysEqual(a, b ssh.PublicKey) bool {
	return a != nil && b != nil && a.Type() == b.Type() && bytes.Equal(a.Marshal(), b.Marshal())
}

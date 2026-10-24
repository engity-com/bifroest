package authorization

import (
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func (this *SimpleAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "simple", this.flow)
	if err != nil {
		return nil, err
	}
	stored, err := this.RestoreFromSession(req.Context(), sess, nil)
	if err != nil {
		return nil, err
	}
	auth := stored.(*simple)
	if !strings.EqualFold(req.Connection().Remote().User(), auth.entry.Name) {
		return nil, ErrSessionResumeDenied
	}
	auth.remote = req.Connection().Remote()
	auth.envVars = nil
	if key != nil {
		policy, accepted, certificate, configured, err := this.authorizedKeyPolicy(resumePublicKeyRequest{req, key}, auth.entry)
		if err != nil {
			return nil, err
		}
		if !accepted {
			if certificate || configured {
				return nil, ErrSessionResumeDenied
			}
			remembered, err := sess.HasPublicKey(req.Context(), key)
			if err != nil {
				return nil, err
			}
			if !remembered {
				return nil, ErrSessionResumeDenied
			}
			auth.sessionsPublicKey = key
		}
		auth.authorizedKeyPolicy = policy
	} else {
		password, err := auth.entry.GetPassword()
		if err != nil {
			return nil, err
		}
		if password.IsZero() {
			return nil, ErrSessionResumeDenied
		}
	}
	return finishSessionResume(req, auth)
}

func (this *HtpasswdAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "htpasswd", this.flow)
	if err != nil {
		return nil, err
	}
	stored, err := this.RestoreFromSession(req.Context(), sess, nil)
	if err != nil {
		return nil, err
	}
	auth := stored.(*htpasswd)
	if auth.principal == "" || req.Connection().Remote().User() != auth.principal {
		return nil, ErrSessionResumeDenied
	}
	found, err := this.conf.File.Contains(auth.principal)
	if err != nil {
		return nil, err
	}
	if !found && !this.conf.Entries.Contains(auth.principal) {
		return nil, ErrSessionResumeDenied
	}
	if key != nil {
		if _, certificate := key.(*ssh.Certificate); certificate {
			return nil, ErrSessionResumeDenied
		}
		remembered, err := sess.HasPublicKey(req.Context(), key)
		if err != nil {
			return nil, err
		}
		if !remembered {
			return nil, ErrSessionResumeDenied
		}
		auth.sessionsPublicKey = key
	}
	auth.remote = req.Connection().Remote()
	auth.envVars = nil
	return finishSessionResume(req, auth)
}

func (this *NoneAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "none", this.flow)
	if err != nil {
		return nil, err
	}
	if _, certificate := key.(*ssh.Certificate); certificate {
		return nil, ErrSessionResumeDenied
	}
	// This is exact-session possession, not an anonymous identity selector. It
	// neither searches for another anonymous session nor creates one.
	auth := &none{remote: req.Connection().Remote(), flow: this.flow, session: sess}
	return finishSessionResume(req, auth)
}

func (this *BifroestAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "bifroest", this.flow)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, ErrSessionResumeDenied
	}
	evidence, policy, accepted, err := evaluateBifroestUserCertificate(key, req.Connection().Remote().User(), this.trustedUserCAs, this.audiences, this.conf.MaxCertificateValidity.Native(), time.Now())
	if err != nil || !accepted {
		return nil, ErrSessionResumeDenied
	}
	// Stored session evidence may belong to an earlier connection with different
	// PTY/forwarding rights. Only this binding's exact, currently valid certificate
	// supplies the resumed connection's claims and policy.
	auth := &BifroestAuthorization{remote: req.Connection().Remote(), flow: this.flow, session: sess, evidence: evidence, policy: policy}
	if retained, err := this.primarySessionReuse(auth)(req.Context(), sess); err != nil {
		return nil, err
	} else if !retained {
		return nil, ErrSessionResumeDenied
	}
	return finishSessionResume(req, auth)
}

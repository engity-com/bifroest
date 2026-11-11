package authorization

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

func (this *SimpleAuthorizer) ResumeSession(req SessionResumeRequest) (Authorization, error) {
	sess, key, err := beginSessionResume(req, "simple", this.flow)
	if err != nil {
		return nil, err
	}
	remoteName, err := resolveRemoteName(req, this.conf.RemoteName)
	if err != nil {
		return nil, err
	}
	if err := checkMappedResumeRemote(req, sess, this.conf.RemoteName); err != nil {
		return nil, err
	}
	stored, err := this.RestoreFromSession(req.Context(), sess, nil)
	if err != nil {
		return nil, err
	}
	auth := stored.(*simple)
	if !strings.EqualFold(remoteName, auth.entry.Name) {
		return nil, ErrSessionResumeDenied
	}
	auth.remote = req.Connection().Remote()
	auth.envVars = nil
	if key != nil {
		policy, accepted, certificate, configured, err := this.authorizedKeyPolicy(resumePublicKeyRequest{req, key}, auth.entry, remoteName)
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
	remoteName, err := resolveRemoteName(req, this.conf.RemoteName)
	if err != nil {
		return nil, err
	}
	if err := checkMappedResumeRemote(req, sess, this.conf.RemoteName); err != nil {
		return nil, err
	}
	stored, err := this.RestoreFromSession(req.Context(), sess, nil)
	if err != nil {
		return nil, err
	}
	auth := stored.(*htpasswd)
	if auth.principal == "" || remoteName != auth.principal {
		return nil, ErrSessionResumeDenied
	}
	found, err := this.containsPrincipal(auth.principal)
	if err != nil {
		return nil, err
	}
	if !found {
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

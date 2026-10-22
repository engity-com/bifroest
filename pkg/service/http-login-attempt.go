package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	goerrors "errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/engity-com/bifroest/pkg/audit"
	"github.com/engity-com/bifroest/pkg/authorization"
)

const (
	webMaximumAttempts        = 64
	webMaximumAttemptsPerPeer = 4
	webAttemptLifetime        = 10 * time.Minute
	webAttemptIdleTimeout     = 90 * time.Second
	webKeyAttemptLifetime     = 2 * time.Minute
	webMaximumLoginSteps      = 32
	webMaximumLoginMessage    = 8 << 10
	webMaximumLoginMessages   = 32 << 10
)

// This permission controls only an in-progress login, never a session or task.
// A worker retains its slot until it has actually returned, including after
// cancellation. A misbehaving authorizer cannot create unbounded detached work.
type webLoginAttempt struct {
	conn         *webLoginConnection
	peer         netip.Addr
	method       audit.AuthenticationMethod
	expires      time.Time
	stopContext  context.CancelFunc
	stopShutdown func() bool
	idle         *time.Timer
	done         chan struct{}
	mutex        sync.Mutex
	consumed     bool
	claiming     bool
	sequence     uint64
	messageBytes int
	step         *webLoginStep
	replies      chan string
	auth         authorization.Authorization
	err          error
}

type webLoginStep struct {
	Sequence  string `json:"sequence"`
	Kind      string `json:"kind"`
	Message   string `json:"message,omitempty"`
	Echo      bool   `json:"echo"`
	Challenge string `json:"challenge,omitempty"`
}

type webLoginPending struct {
	Status          string        `json:"status"`
	AttemptToken    string        `json:"attemptToken,omitempty"`
	ExpiresAt       time.Time     `json:"expiresAt"`
	PollAfterMillis int           `json:"pollAfterMillis"`
	Step            *webLoginStep `json:"step,omitempty"`
}

func webAttemptKey(token string) ([32]byte, bool) {
	if len(token) != 48 || token[:5] != "bwl1." {
		return [32]byte{}, false
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(token[5:])
	if err != nil || len(value) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(token)), true
}

func (this *webService) startAttempt(r *http.Request, scope webScope, peer netip.Addr, user string, method audit.AuthenticationMethod, key ssh.PublicKey) (string, *webLoginAttempt, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", nil, err
	}
	token := "bwl1." + base64.RawURLEncoding.EncodeToString(nonce[:])
	index, _ := webAttemptKey(token)
	lifetime := webAttemptLifetime
	if key != nil {
		lifetime = webKeyAttemptLifetime
	}
	// Keep trusted request values (e.g. the operator's OIDC HTTP client), not its
	// cancellation: normal HTTP completion must not cancel a multi-step login.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), lifetime)
	stopShutdown := context.AfterFunc(this.ctx, cancel)
	conn, err := newWebLoginConnection(ctx, r, scope, user)
	if err != nil {
		stopShutdown()
		cancel()
		return "", nil, err
	}
	expires, _ := ctx.Deadline()
	attempt := &webLoginAttempt{conn: conn, peer: peer, method: method, expires: expires, stopContext: cancel, stopShutdown: stopShutdown, done: make(chan struct{})}
	attempt.idle = time.AfterFunc(webAttemptIdleTimeout, cancel)
	this.mutex.Lock()
	this.pruneLocked(time.Now())
	count := 0
	for _, entry := range this.attempts {
		if entry.peer == peer {
			count++
		}
	}
	release, accepting := this.loginWorkers.register()
	_, collision := this.attempts[index]
	if !accepting || this.ctx.Err() != nil || len(this.attempts) >= webMaximumAttempts || count >= webMaximumAttemptsPerPeer || collision {
		this.mutex.Unlock()
		if accepting {
			release()
		}
		attempt.stop()
		return "", nil, fmt.Errorf("login attempt capacity unavailable")
	}
	this.attempts[index] = attempt
	this.mutex.Unlock()
	go func() {
		defer release()
		var auth authorization.Authorization
		var err error
		if key == nil {
			auth, err = this.service.authorizer.AuthorizeInteractive(&webInteractiveRequest{authorizeRequest: authorizeRequest{service: this.service, connection: conn}, attempt: attempt})
		} else {
			auth, err = this.authorizeWebKey(attempt, key)
		}
		attempt.mutex.Lock()
		attempt.auth, attempt.err = auth, err
		attempt.step = nil
		attempt.replies = nil
		close(attempt.done)
		attempt.mutex.Unlock()
	}()
	return token, attempt, nil
}

func (this *webLoginAttempt) stop() {
	this.idle.Stop()
	this.stopShutdown()
	this.stopContext()
	_ = this.conn.Close()
}

func (this *webService) findAttempt(scope webScope, peer netip.Addr, token string) (*webLoginAttempt, error) {
	index, ok := webAttemptKey(token)
	if !ok {
		return nil, fmt.Errorf("login attempt denied")
	}
	this.mutex.Lock()
	defer this.mutex.Unlock()
	attempt := this.attempts[index]
	if this.ctx.Err() != nil || attempt == nil || attempt.conn.scope != scope || attempt.peer != peer {
		return nil, fmt.Errorf("login attempt denied")
	}
	attempt.mutex.Lock()
	defer attempt.mutex.Unlock()
	if attempt.consumed || attempt.conn.IsClosed() {
		return nil, fmt.Errorf("login attempt denied")
	}
	return attempt, nil
}

// Exactly one outstanding step and one bounded reply. Messages are plain text,
// not HTML, terminal output or shell input. Answers are never returned by polls.
func (this *webLoginAttempt) exchange(step webLoginStep) (string, error) {
	if len(step.Message) > webMaximumLoginMessage || !utf8.ValidString(step.Message) {
		return "", fmt.Errorf("login message exceeds limit")
	}
	this.mutex.Lock()
	if this.consumed || this.conn.IsClosed() || this.step != nil || this.replies != nil || this.sequence >= webMaximumLoginSteps || this.messageBytes+len(step.Message) > webMaximumLoginMessages {
		this.mutex.Unlock()
		return "", fmt.Errorf("login interaction unavailable")
	}
	this.sequence++
	this.messageBytes += len(step.Message)
	step.Sequence = strconv.FormatUint(this.sequence, 10)
	replies := make(chan string, 1)
	this.step = &step
	this.replies = replies
	this.mutex.Unlock()
	select {
	case <-this.conn.Lifetime().Done():
		return "", this.conn.Lifetime().Err()
	case answer := <-replies:
		if err := this.conn.Lifetime().Err(); err != nil {
			return "", err
		}
		return answer, nil
	}
}

type webInteractiveRequest struct {
	authorizeRequest
	attempt *webLoginAttempt
}

func (this *webInteractiveRequest) SendInfo(message string) error {
	_, err := this.attempt.exchange(webLoginStep{Kind: "info", Message: message})
	return err
}
func (this *webInteractiveRequest) SendError(message string) error {
	_, err := this.attempt.exchange(webLoginStep{Kind: "error", Message: message})
	return err
}
func (this *webInteractiveRequest) Prompt(message string, echo bool) (string, error) {
	return this.attempt.exchange(webLoginStep{Kind: "prompt", Message: message, Echo: echo})
}

func (this *webService) handleAttempt(w http.ResponseWriter, r *http.Request, scope webScope, peer netip.Addr, values map[string]string) {
	if r.URL.Path == webAPI+"login/interactive" || r.URL.Path == webAPI+"login/public-key" {
		isKey := r.URL.Path == webAPI+"login/public-key"
		expected := 2
		if isKey {
			expected = 3
		}
		if len(values) != expected || !validWebLoginUser(values["user"]) {
			webError(w, http.StatusBadRequest, "invalid login request")
			return
		}
		var key ssh.PublicKey
		var err error
		method := audit.AuthenticationMethodKeyboardInteractive
		if isKey {
			key, err = parseWebPublicKey(values["publicKey"])
			if err != nil {
				webError(w, http.StatusBadRequest, "unsupported public key")
				return
			}
			method = audit.AuthenticationMethodPublicKey
		}
		token, attempt, err := this.startAttempt(r, scope, peer, values["user"], method, key)
		if err != nil {
			w.Header().Set("Retry-After", "60")
			webError(w, http.StatusTooManyRequests, "login attempt limit reached")
			return
		}
		attempt.mutex.Lock()
		pending := attempt.pending(token)
		attempt.mutex.Unlock()
		webJSONResponse(w, http.StatusAccepted, pending)
		return
	}
	if r.URL.Path != webAPI+"login/reply" && len(values) != 1 {
		webError(w, http.StatusBadRequest, "only slug is accepted")
		return
	}
	attempt, err := this.findAttempt(scope, peer, webBearer(r))
	if err != nil {
		webError(w, http.StatusUnauthorized, "login attempt denied")
		return
	}
	switch r.URL.Path {
	case webAPI + "login/poll":
		this.pollAttempt(w, r, attempt)
	case webAPI + "login/reply":
		this.replyAttempt(w, attempt, values)
	case webAPI + "login/cancel":
		attempt.mutex.Lock()
		if attempt.consumed {
			attempt.mutex.Unlock()
			webError(w, http.StatusConflict, "login attempt already consumed")
			return
		}
		attempt.consumed = true
		attempt.mutex.Unlock()
		attempt.stop()
		this.pruneAttempts()
		w.WriteHeader(http.StatusNoContent)
	}
}

func (this *webLoginAttempt) pending(token string) webLoginPending {
	var step *webLoginStep
	if this.step != nil {
		snapshot := *this.step
		step = &snapshot
	}
	return webLoginPending{Status: "pending", AttemptToken: token, ExpiresAt: this.expires, PollAfterMillis: 1000, Step: step}
}

func (this *webService) pollAttempt(w http.ResponseWriter, r *http.Request, attempt *webLoginAttempt) {
	attempt.mutex.Lock()
	if attempt.consumed || attempt.conn.IsClosed() {
		attempt.mutex.Unlock()
		webError(w, http.StatusUnauthorized, "login attempt denied")
		return
	}
	attempt.idle.Reset(webAttemptIdleTimeout)
	select {
	case <-attempt.done:
		attempt.consumed = true
		attempt.claiming = true
		auth, err := attempt.auth, attempt.err
		attempt.mutex.Unlock()
		defer func() {
			attempt.stop()
			attempt.mutex.Lock()
			attempt.claiming = false
			attempt.mutex.Unlock()
			this.pruneAttempts()
		}()
		if err != nil {
			if goerrors.Is(err, errWebKeyProof) {
				webError(w, http.StatusUnauthorized, "authentication denied")
			} else {
				webError(w, http.StatusServiceUnavailable, "authentication unavailable")
			}
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		stop := context.AfterFunc(attempt.conn.Lifetime(), cancel)
		defer stop()
		this.completeAuthentication(w, ctx, attempt.conn, auth, attempt.method)
	default:
		pending := attempt.pending("")
		attempt.mutex.Unlock()
		w.Header().Set("Retry-After", "1")
		webJSONResponse(w, http.StatusOK, pending)
	}
}

func (this *webService) replyAttempt(w http.ResponseWriter, attempt *webLoginAttempt, values map[string]string) {
	pending, status, message := attempt.acceptReply(values)
	if message != "" {
		webError(w, status, message)
		return
	}
	webJSONResponse(w, status, pending)
}

func (attempt *webLoginAttempt) acceptReply(values map[string]string) (webLoginPending, int, string) {
	attempt.mutex.Lock()
	defer attempt.mutex.Unlock()
	if attempt.consumed || attempt.conn.IsClosed() {
		return webLoginPending{}, http.StatusUnauthorized, "login attempt denied"
	}
	step := attempt.step
	if step == nil || step.Sequence != values["sequence"] {
		return webLoginPending{}, http.StatusConflict, "stale login step"
	}
	answer := ""
	valid := false
	switch step.Kind {
	case "info", "error":
		valid = len(values) == 2
	case "prompt":
		answer = values["answer"]
		_, present := values["answer"]
		valid = present && len(values) == 3 && len(answer) <= 4096
	case "public-key":
		answer = values["signature"]
		_, present := values["signature"]
		valid = present && len(values) == 3 && len(answer) <= 12<<10
	}
	if !valid {
		return webLoginPending{}, http.StatusBadRequest, "invalid login reply"
	}
	attempt.idle.Reset(webAttemptIdleTimeout)
	replies := attempt.replies
	attempt.step = nil
	attempt.replies = nil
	replies <- answer
	return attempt.pending(""), http.StatusAccepted, ""
}

func (this *webService) pruneAttempts() {
	this.mutex.Lock()
	this.pruneLocked(time.Now())
	this.mutex.Unlock()
}

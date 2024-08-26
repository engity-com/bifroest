package environment

import (
	"bytes"
	"context"
	"fmt"
	"io"

	gencoding "github.com/gdamore/encoding"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	dpkg "github.com/engity-com/bifroest/pkg/dummy"
	"github.com/engity-com/bifroest/pkg/errors"
	"github.com/engity-com/bifroest/pkg/session"
)

func init() {
	tcell.RegisterEncoding("UTF-16", gencoding.UTF8)
}

type dummy struct {
	repository *DummyRepository
	session    session.Session
}

func (this *dummy) Session() session.Session {
	return this.session
}

func (this *dummy) Banner(Request) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}

func (this *dummy) introduction(req Request) (string, error) {
	b, err := this.repository.conf.Introduction.Render(req)
	if err != nil {
		return "", err
	}

	return b, nil
}

func (this *dummy) Run(t Task) (exitCode int, rErr error) {
	switch t.TaskType() {
	case TaskTypeShell:
		// Ok.
	case TaskTypeSftp:
		return -1, fmt.Errorf("sftp not supported by dummy environment")
	default:
		return -1, fmt.Errorf("illegal task type: %v", t.TaskType())
	}

	ptyReq, winCh, isPty := t.SshSession().Pty()
	if !isPty {
		return -1, fmt.Errorf("dummy environment requires a PTY, but current SSH sessions does not support it")
	}

	introduction, err := this.repository.conf.Introduction.Render(t)
	if err != nil {
		return -1, fmt.Errorf("cannot render introduction: %w", err)
	}
	if introductionStyled, err := this.repository.conf.IntroductionStyled.Render(t); err != nil {
		return -1, fmt.Errorf("cannot render introduction: %w", err)
	} else if !introductionStyled {
		introduction = tview.Escape(introduction)
	}

	tty := &dummyTty{
		session:       t.SshSession(),
		environment:   this,
		windowChannel: winCh,
		window:        ptyReq.Window,
	}

	ti, err := tcell.LookupTerminfo(ptyReq.Term)
	if err != nil {
		return -1, fmt.Errorf("cannot resolve terminfo: %w", err)
	}

	s, err := tcell.NewTerminfoScreenFromTtyTerminfo(tty, ti)
	if err != nil {
		return -1, fmt.Errorf("cannot create screen: %w", err)
	}

	d := &dpkg.Dummy{
		Screen:       s,
		Introduction: introduction,
		ShowEvents:   true,
	}

	if err := d.Execute(); err != nil {
		return -1, err
	}

	s.Fini()
	_, _ = fmt.Fprintf(tty, "Bye!\n\n")
	return 0, nil
}

func (this *dummy) Dispose(ctx context.Context) (bool, error) {
	fail := func(err error) (bool, error) {
		return false, errors.Newf(errors.System, "cannot dispose environment: %w", err)
	}

	if sess := this.session; sess != nil {
		if err := sess.SetEnvironmentToken(ctx, nil); err != nil {
			return fail(err)
		}
	}

	return true, nil
}

func (this *dummy) IsPortForwardingAllowed(_ string, _ uint32) (bool, error) {
	return false, nil
}

func (this *dummy) NewDestinationConnection(ctx context.Context, host string, port uint32) (io.ReadWriteCloser, error) {
	return nil, errors.Newf(errors.Permission, "portforwarning not allowed")
}

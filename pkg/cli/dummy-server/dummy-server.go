package dummy_server

import (
	"context"
	"fmt"
	gonet "net"
	"net/http"
	goos "os"
	"os/signal"
	"strings"
	"syscall"

	cli "github.com/echocat/cli4g"
	log "github.com/echocat/slf4g"

	cliCommon "github.com/engity-com/bifroest/pkg/cli/common"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
)

type opts struct {
	Addr string `flag:"addr" default:":8783" placeholder:"[<host>]:<port>" description:"Address to bind to."`
}

func Register(c cli.ContainerRequirementSetters) {
	c.AddCommand(cli.NewCommand[opts]("dummy-server", "This is a supporting command which simply runs forever until it receives a interrupt signal.").
		WithProfiles(cliCommon.ProfileExecutable).
		WithVisible(false).
		WithHandler(handler),
	)
}

func handler(_ context.Context, o opts) (rErr error) {
	ln, err := gonet.Listen("tcp", o.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen to address %q: %w", o.Addr, err)
	}
	defer common.IgnoreCloseError(ln)

	srv := http.Server{Handler: newDummyMux()}

	sigs := make(chan goos.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigs
		log.With("signal", s).
			Info("received signal")
		_ = srv.Shutdown(context.Background())
	}()

	log.With("addr", o.Addr).
		Info("listen...")

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to serve at %q: %w", o.Addr, err)
	}

	log.Info("bye!")

	return nil
}

func newDummyMux() http.Handler {
	return http.HandlerFunc(dummyServerHandleIndex)
}

func dummyServerHandleIndex(w http.ResponseWriter, r *http.Request) {
	var err error
	var status = http.StatusOK
	defer logDummyRequest(r, status, err)

	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodHead, http.MethodDelete, http.MethodPatch, http.MethodPut:
	default:
		status = http.StatusMethodNotAllowed
		w.WriteHeader(status)
		return
	}
	w.WriteHeader(status)
	header := w.Header()
	header.Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = fmt.Fprintf(w, `Hello from a dummy-server!

Called URI: %v
Method:     %v
Host:       %v
Your Host:  %v

`, r.RequestURI, r.Method, r.Host, r.RemoteAddr)
}

func logDummyRequest(r *http.Request, status int, err error) {
	f := map[string]any{
		"host":   r.Host,
		"uri":    r.RequestURI,
		"method": r.Method,
		"status": status,
		"remote": r.RemoteAddr,
	}
	for k, v := range r.Header {
		if len(v) == 1 {
			f["header-"+strings.ToLower(k)] = v[0]
		} else {
			f["header-"+strings.ToLower(k)] = v
		}
	}
	l := log.WithAll(f)
	if err != nil {
		l.With("error", err).
			Error("request failed")
	} else {
		l.Info("request succeeded")
	}

}

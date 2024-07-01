package main

import (
	"context"
	"fmt"
	"github.com/alecthomas/kingpin"
	log "github.com/echocat/slf4g"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var (
	addr = ":8783"
)

var _ = registerCommand(func(app *kingpin.Application) {
	cmd := app.Command("dummy-server", "This is a supporting command which simply runs forever until it receives a interrupt signal.").
		Hidden().
		Action(func(*kingpin.ParseContext) error {
			return doDummyServer()
		})
	cmd.Flag("addr", "Address to bind to. Default: "+addr).
		PlaceHolder("[<host>]:<port>").
		StringVar(&addr)
})

func doDummyServer() (rErr error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen to address %q: %w", addr, err)
	}
	defer common.IgnoreCloseError(ln)

	srv := http.Server{Handler: newDummyMux()}

	sigs := make(chan os.Signal, 1)
	defer close(sigs)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigs
		log.With("signal", s).
			Info("received signal")
		_ = srv.Shutdown(context.Background())
	}()

	log.With("addr", addr).
		Info("listen...")

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to serve at %q: %w", addr, err)
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
	_, err = fmt.Fprintf(w, `Hello from a dummy-server!

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

package main

import (
	"context"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	gos "os"
	"path/filepath"
	"time"

	"github.com/alecthomas/kingpin"
	log "github.com/echocat/slf4g"
	"github.com/gwatts/rootcerts/certparse"

	"github.com/engity-com/bifroest/pkg/common"
)

const (
	certdataDownloadUrl = "https://hg.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt"
)

var (
	defaultCaCertsTargetFn = filepath.Join("pkg", "crypto", "ca-certs.crt")
)

func newDependenciesCaCerts(b *dependencies) *dependenciesCaCerts {
	return &dependenciesCaCerts{
		dependencies: b,

		sourceUrl:  certdataDownloadUrl,
		targetFile: defaultCaCertsTargetFn,
	}
}

type dependenciesCaCerts struct {
	dependencies *dependencies

	sourceUrl  string
	targetFile string
}

func (this *dependenciesCaCerts) init(ctx context.Context, app *kingpin.Application) {
	cmd := app.Command("ca-certs", "")

	app.Flag("caCertsUrl", "").
		Default(this.sourceUrl).
		StringVar(&this.sourceUrl)
	app.Flag("caCertsTargetPemFile", "").
		Default(this.targetFile).
		StringVar(&this.targetFile)

	cmdPem := cmd.Command("pem", "")
	cmdPem.Action(func(*kingpin.ParseContext) error {
		return this.generatePem(ctx)
	})
}

func (this *dependenciesCaCerts) generatePem(ctx context.Context) (rErr error) {
	var f *gos.File
	if this.targetFile == "stdout" {
		f = gos.Stdout
	} else {
		var err error
		if f, err = gos.OpenFile(this.targetFile, gos.O_CREATE|gos.O_WRONLY|gos.O_TRUNC, 0644); err != nil {
			return err
		}
		defer common.KeepCloseError(&rErr, f)
	}

	return this.generate(ctx, f)
}

func (this *dependenciesCaCerts) generate(ctx context.Context, to io.Writer) error {
	fail := func(err error) error {
		return fmt.Errorf("cannot generate ca-certs from %s: %w", this.sourceUrl, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	start := time.Now()
	l := log.With("source", this.sourceUrl)

	l.Debug("downloading ca-certs...")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, this.sourceUrl, nil)
	if err != nil {
		return fail(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return failf("illegal response code: %d", resp.StatusCode)
	}
	defer common.IgnoreCloseError(resp.Body)

	certs, err := certparse.ReadTrustedCerts(resp.Body)
	if err != nil {
		return fail(err)
	}

	for _, cert := range certs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if (cert.Trust & certparse.ServerTrustedDelegator) == 0 {
			continue
		}

		log.With("subject", cert.Cert.Subject).
			With("label", cert.Label).
			With("serial", hex.EncodeToString(cert.Cert.SerialNumber.Bytes())).
			Trace("ca cert added")

		if err := pem.Encode(to, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Data,
		}); err != nil {
			return fail(err)
		}
	}

	l = l.With("duration", time.Since(start).Truncate(time.Millisecond))
	if l.IsDebugEnabled() {
		l.Info("downloading ca-certs... DONE!")
	} else {
		l.Info("ca-certs downloaded")
	}

	return nil
}

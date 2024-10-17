package protocol

import "crypto/tls"

var (
	minTlsVersion   uint16 = tls.VersionTLS13
	tlsCipherSuites        = []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
)

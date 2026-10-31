package net

import (
	"fmt"
	stdnet "net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

const MaxHttpSlugSegmentBytes = 64

// CanonicalHttpHost normalizes an HTTP authority to its host without a port.
// IPv6 addresses retain brackets, making canonical values valid authorities
// themselves and keeping normalization idempotent.
// It does not grant access to that host: the endpoint must separately enforce
// its configured domain allowlist, SNI policy and request origin.
func CanonicalHttpHost(authority string) (string, error) {
	if authority == "" || strings.ContainsAny(authority, " \t\r\n/@\\?#%") {
		return "", fmt.Errorf("invalid HTTP host")
	}
	host := authority
	if strings.Contains(authority, ":") {
		if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
			host = authority[1 : len(authority)-1]
		} else {
			var port string
			var err error
			host, port, err = stdnet.SplitHostPort(authority)
			if err != nil {
				return "", fmt.Errorf("invalid HTTP host or port")
			}
			for _, character := range port {
				if character < '0' || character > '9' {
					return "", fmt.Errorf("invalid HTTP port")
				}
			}
			if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
				return "", fmt.Errorf("invalid HTTP port")
			}
		}
	}
	address, addressErr := netip.ParseAddr(host)
	if strings.HasPrefix(authority, "[") && (addressErr != nil || address.Is4()) {
		return "", fmt.Errorf("invalid bracketed HTTP host")
	}
	if addressErr == nil {
		if !address.Is4() {
			return "[" + address.String() + "]", nil
		}
		return address.String(), nil
	}
	if strings.ContainsAny(host, ":[]") {
		return "", fmt.Errorf("invalid HTTP host")
	}
	host = strings.TrimSuffix(host, ".")
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" || len(ascii) > 253 {
		return "", fmt.Errorf("invalid HTTP hostname")
	}
	ascii = strings.ToLower(ascii)
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid HTTP hostname label")
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return "", fmt.Errorf("invalid HTTP hostname label")
		}
	}
	return ascii, nil
}

// ValidateHttpSlug accepts the root slug or one/two case-sensitive ASCII
// alphanumeric segments, each at most MaxHttpSlugSegmentBytes bytes long.
// Internal routes use a different namespace, not a more permissive slug grammar.
func ValidateHttpSlug(slug string) error {
	if slug == "" {
		return nil
	}
	segments := strings.Split(slug, "/")
	if len(segments) > 2 {
		return fmt.Errorf("HTTP slug must contain at most two segments")
	}
	for _, segment := range segments {
		if len(segment) == 0 || len(segment) > MaxHttpSlugSegmentBytes {
			return fmt.Errorf("HTTP slug segment must contain 1 to %d bytes", MaxHttpSlugSegmentBytes)
		}
		for _, character := range segment {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
				continue
			}
			return fmt.Errorf("HTTP slug segments must be ASCII alphanumeric")
		}
	}
	return nil
}

// HttpSlugFromURL ignores query/fragment but rejects encoded path aliases and
// trailing slashes. Call this before discarding URL.RawPath at the HTTP boundary.
func HttpSlugFromURL(value *url.URL) (string, error) {
	if value == nil || value.Opaque != "" || strings.Contains(value.EscapedPath(), "%") || (value.RawPath != "" && value.RawPath != value.Path) {
		return "", fmt.Errorf("invalid or encoded HTTP slug path")
	}
	path := value.Path
	if path == "" || path == "/" {
		return "", nil
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("HTTP slug path must be absolute")
	}
	slug := path[1:]
	if err := ValidateHttpSlug(slug); err != nil {
		return "", err
	}
	return slug, nil
}

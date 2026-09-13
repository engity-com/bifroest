// Copyright 2015 Gareth Watts
// Licensed under an MIT license
// See LICENSES/MIT.txt for details.
// SPDX-License-Identifier: MIT

// Package certdata parses Mozilla NSS certdata.txt files.
//
// This parser is derived from github.com/gwatts/rootcerts/certparse at
// revision d711a5bdf9bddbbff967bfc4bb018fe0e748fae8.
package certdata

import (
	"bufio"
	"crypto/sha1" // #nosec G505 -- Mozilla NSS uses SHA-1 as the trust-object identifier.
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	classCertificate = "CKO_CERTIFICATE"
	classTrust       = "CKO_NSS_TRUST"

	TrustUnspecified      Trust = ""
	TrustTrustedDelegator Trust = "CKT_NSS_TRUSTED_DELEGATOR"
	TrustMustVerify       Trust = "CKT_NSS_MUST_VERIFY_TRUST"
	TrustNotTrusted       Trust = "CKT_NSS_NOT_TRUSTED"
)

// Trust is a Mozilla NSS trust level.
type Trust string

// Certificate contains a certificate and its server-authentication metadata.
type Certificate struct {
	Label               string
	DER                 []byte
	ServerTrust         Trust
	ServerDistrustAfter *time.Time
}

// ReadCertificates parses all certificate objects and associates their
// server-authentication trust objects by Mozilla's certificate hash.
func ReadCertificates(from io.Reader) ([]Certificate, error) {
	objects, err := readObjects(from)
	if err != nil {
		return nil, err
	}

	type trustMetadata struct {
		label         string
		trust         Trust
		distrustAfter *time.Time
	}
	trustByHash := make(map[[sha1.Size]byte]trustMetadata)
	for _, object := range objects {
		class := object["CKA_CLASS"]
		if class.value != classTrust {
			continue
		}
		if class.type_ != "CK_OBJECT_CLASS" {
			return nil, fmt.Errorf("trust object has illegal CKA_CLASS type %q", class.type_)
		}
		labelField := object["CKA_LABEL"]
		label := labelField.value
		if label == "" {
			return nil, errors.New("trust object without CKA_LABEL")
		}
		if labelField.type_ != "UTF8" {
			return nil, fmt.Errorf("trust object %q has illegal CKA_LABEL type %q", label, labelField.type_)
		}
		trustField := object["CKA_TRUST_SERVER_AUTH"]
		if trustField.field != "" && trustField.type_ != "CK_TRUST" {
			return nil, fmt.Errorf("certificate %q has illegal CKA_TRUST_SERVER_AUTH type %q", label, trustField.type_)
		}
		trust, err := parseTrust(trustField.value)
		if err != nil {
			return nil, fmt.Errorf("certificate %q: %w", label, err)
		}
		distrustAfter, err := parseDistrustAfter(object, "CKA_NSS_SERVER_DISTRUST_AFTER")
		if err != nil {
			return nil, fmt.Errorf("certificate %q trust object: %w", label, err)
		}
		hashField := object["CKA_CERT_SHA1_HASH"]
		if hashField.field != "" && hashField.type_ != "MULTILINE_OCTAL" {
			return nil, fmt.Errorf("certificate %q trust object has illegal CKA_CERT_SHA1_HASH type %q", label, hashField.type_)
		}
		rawHash := []byte(hashField.value)
		if len(rawHash) != sha1.Size {
			return nil, fmt.Errorf("certificate %q trust object has an illegal CKA_CERT_SHA1_HASH", label)
		}
		var hash [sha1.Size]byte
		copy(hash[:], rawHash)
		if _, exists := trustByHash[hash]; exists {
			return nil, fmt.Errorf("duplicate trust object for certificate hash %X", hash)
		}
		trustByHash[hash] = trustMetadata{label: label, trust: trust, distrustAfter: distrustAfter}
	}

	seenCertificates := make(map[string]struct{})
	matchedTrust := make(map[[sha1.Size]byte]struct{})
	result := make([]Certificate, 0, len(trustByHash))
	for _, object := range objects {
		class := object["CKA_CLASS"]
		if class.value != classCertificate {
			continue
		}
		if class.type_ != "CK_OBJECT_CLASS" {
			return nil, fmt.Errorf("certificate object has illegal CKA_CLASS type %q", class.type_)
		}
		labelField := object["CKA_LABEL"]
		label := labelField.value
		if label == "" {
			return nil, errors.New("certificate object without CKA_LABEL")
		}
		if labelField.type_ != "UTF8" {
			return nil, fmt.Errorf("certificate %q has illegal CKA_LABEL type %q", label, labelField.type_)
		}
		valueField := object["CKA_VALUE"]
		if valueField.field != "" && valueField.type_ != "MULTILINE_OCTAL" {
			return nil, fmt.Errorf("certificate %q has illegal CKA_VALUE type %q", label, valueField.type_)
		}
		der := []byte(valueField.value)
		if len(der) == 0 {
			return nil, fmt.Errorf("certificate %q without CKA_VALUE", label)
		}
		if _, exists := seenCertificates[string(der)]; exists {
			return nil, fmt.Errorf("duplicate certificate object for certificate %q", label)
		}
		seenCertificates[string(der)] = struct{}{}
		distrustAfter, err := parseDistrustAfter(object, "CKA_NSS_SERVER_DISTRUST_AFTER")
		if err != nil {
			return nil, fmt.Errorf("certificate %q: %w", label, err)
		}
		identifier := mozillaTrustIdentifier(der)
		trust := trustByHash[identifier]
		if trust.label != "" {
			matchedTrust[identifier] = struct{}{}
		}
		if distrustAfter != nil && trust.distrustAfter != nil && !distrustAfter.Equal(*trust.distrustAfter) {
			return nil, fmt.Errorf("certificate %q has conflicting CKA_NSS_SERVER_DISTRUST_AFTER values", label)
		}
		if distrustAfter == nil {
			distrustAfter = trust.distrustAfter
		}
		result = append(result, Certificate{
			Label:               label,
			DER:                 der,
			ServerTrust:         trust.trust,
			ServerDistrustAfter: distrustAfter,
		})
	}
	for hash, trust := range trustByHash {
		if trust.trust == TrustTrustedDelegator {
			if _, matched := matchedTrust[hash]; !matched {
				return nil, fmt.Errorf("trusted object %q has no matching certificate", trust.label)
			}
		}
	}

	return result, nil
}

func mozillaTrustIdentifier(der []byte) [sha1.Size]byte {
	return sha1.Sum(der) //nolint:gosec // This must match the SHA-1 identifier supplied by Mozilla NSS.
}

func parseTrust(value string) (Trust, error) {
	trust := Trust(value)
	switch trust {
	case TrustUnspecified, TrustTrustedDelegator, TrustMustVerify, TrustNotTrusted:
		return trust, nil
	default:
		return "", fmt.Errorf("unknown server trust level %q", value)
	}
}

func parseDistrustAfter(object map[string]value, field string) (*time.Time, error) {
	attribute, exists := object[field]
	if !exists {
		return nil, nil
	}
	value := attribute.value
	if attribute.type_ == "CK_BBOOL" && value == "CK_FALSE" {
		return nil, nil
	}
	if attribute.type_ != "MULTILINE_OCTAL" {
		return nil, fmt.Errorf("illegal %s type %q", field, attribute.type_)
	}
	if value == "" {
		return nil, fmt.Errorf("empty %s value", field)
	}

	switch len(value) {
	case len("060102150405Z"):
		year, err := strconv.Atoi(value[:2])
		if err != nil {
			return nil, fmt.Errorf("illegal %s value %q: %w", field, value, err)
		}
		if year < 50 {
			year += 2000
		} else {
			year += 1900
		}
		value = fmt.Sprintf("%04d%s", year, value[2:])
	case len("20060102150405Z"):
	default:
		return nil, fmt.Errorf("illegal %s value %q", field, value)
	}
	parsed, err := time.Parse("20060102150405Z", value)
	if err != nil {
		return nil, fmt.Errorf("illegal %s value %q: %w", field, value, err)
	}
	return &parsed, nil
}

type value struct {
	field string
	type_ string
	value string
}

type scanner struct {
	s             *bufio.Scanner
	line          int
	skippedHeader bool
	last          value
	err           error
}

func newScanner(from io.Reader) *scanner {
	s := bufio.NewScanner(from)
	s.Buffer(make([]byte, 64*1024), 5*1024*1024)
	return &scanner{s: s}
}

func (this *scanner) scan() bool {
	this.err = nil
	if !this.skippedHeader {
		if err := this.skipHeader(); err != nil {
			this.err = err
			return false
		}
	}

	for this.s.Scan() {
		line := strings.TrimSpace(this.s.Text())
		this.line++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		field, remainder := takeToken(line)
		type_, rawValue := takeToken(remainder)
		if field == "" || type_ == "" {
			this.err = this.errorf("malformed field line")
			return false
		}
		current := value{field: field, type_: type_}
		switch {
		case current.type_ == "UTF8":
			if rawValue == "" {
				this.err = this.errorf("missing UTF8 value for %s", current.field)
				return false
			}
			current.value, this.err = strconv.Unquote(rawValue)
			if this.err != nil {
				this.err = this.errorf("cannot parse UTF8 value for %s: %v", current.field, this.err)
				return false
			}
		case strings.HasPrefix(current.type_, "MULTILINE_"):
			if rawValue != "" {
				this.err = this.errorf("unexpected value after %s for %s", current.type_, current.field)
				return false
			}
			if current.type_ == "MULTILINE_OCTAL" {
				current.value, this.err = this.readMultilineOctal()
			} else {
				_, this.err = this.readMultiline(nil)
			}
			if this.err != nil {
				return false
			}
		case rawValue != "":
			current.value = rawValue
		default:
			this.err = this.errorf("missing value for %s", current.field)
			return false
		}

		this.last = current
		return true
	}
	if err := this.s.Err(); err != nil {
		this.err = this.errorf("cannot read input: %v", err)
	}
	return false
}

func takeToken(value string) (string, string) {
	value = strings.TrimLeftFunc(value, unicode.IsSpace)
	separator := strings.IndexFunc(value, unicode.IsSpace)
	if separator < 0 {
		return value, ""
	}
	return value[:separator], strings.TrimLeftFunc(value[separator:], unicode.IsSpace)
}

func (this *scanner) skipHeader() error {
	for this.s.Scan() {
		this.line++
		if strings.TrimSpace(this.s.Text()) == "BEGINDATA" {
			this.skippedHeader = true
			return nil
		}
	}
	if err := this.s.Err(); err != nil {
		return this.errorf("cannot read input: %v", err)
	}
	return this.errorf("BEGINDATA line not found")
}

func (this *scanner) readMultilineOctal() (string, error) {
	return this.readMultiline(func(line string, result *strings.Builder) error {
		if len(line)%4 != 0 {
			return this.errorf("illegal multiline octal value")
		}
		for offset := 0; offset < len(line); offset += 4 {
			if line[offset] != '\\' {
				return this.errorf("illegal multiline octal value")
			}
			n, err := strconv.ParseUint(line[offset+1:offset+4], 8, 8)
			if err != nil {
				return this.errorf("illegal multiline octal value: %v", err)
			}
			result.WriteByte(byte(n))
		}
		return nil
	})
}

func (this *scanner) readMultiline(consume func(string, *strings.Builder) error) (string, error) {
	var result strings.Builder
	for this.s.Scan() {
		line := this.s.Text()
		this.line++
		if line == "END" {
			return result.String(), nil
		}
		if consume != nil {
			if err := consume(line, &result); err != nil {
				return "", err
			}
		}
	}
	if err := this.s.Err(); err != nil {
		return "", this.errorf("cannot read multiline value: %v", err)
	}
	return "", this.errorf("unexpected EOF in multiline value")
}

func (this *scanner) errorf(message string, args ...any) error {
	return fmt.Errorf("certdata line %d: %s", this.line, fmt.Sprintf(message, args...))
}

func readObjects(from io.Reader) ([]map[string]value, error) {
	scanner := newScanner(from)
	var result []map[string]value
	var current map[string]value
	for scanner.scan() {
		currentValue := scanner.last
		if currentValue.field == "CKA_CLASS" {
			if current != nil {
				result = append(result, current)
			}
			current = make(map[string]value)
		}
		if current == nil {
			return nil, scanner.errorf("field %s outside an object", currentValue.field)
		}
		if _, exists := current[currentValue.field]; exists {
			return nil, scanner.errorf("duplicate field %s", currentValue.field)
		}
		current[currentValue.field] = currentValue
	}
	if scanner.err != nil {
		return nil, scanner.err
	}
	if current != nil {
		result = append(result, current)
	}
	return result, nil
}

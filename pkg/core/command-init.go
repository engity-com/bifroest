package core

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/vmihailenco/msgpack/v5"
	"io"
)

const (
	CommandMagicMarker string = "EPc1"
	CommandVersion     uint16 = 1
)

var (
	ErrIllegalCommandHeaderIntroduction = errors.New("illegal command header introduction")
)

func ReadCommandHeader(from io.Reader) (un string, ck ConfigurationKey, client string, err error) {
	fail := func(err error) (string, ConfigurationKey, string, error) {
		return "", "", "", err
	}
	failf := func(message string, args ...any) (string, ConfigurationKey, string, error) {
		return fail(fmt.Errorf(message, args...))
	}

	mmBuf := make([]byte, len(CommandMagicMarker))
	if _, err = io.ReadFull(from, mmBuf); errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fail(ErrIllegalCommandHeaderIntroduction)
	} else if err != nil {
		return failf("cannot decode magic marker: %w", err)
	}
	if !bytes.Equal(mmBuf, []byte(CommandMagicMarker)) {
		return fail(ErrIllegalCommandHeaderIntroduction)
	}

	dec := msgpack.NewDecoder(from)

	if v, err := dec.DecodeUint16(); errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return fail(ErrIllegalCommandHeaderIntroduction)
	} else if err != nil {
		return failf("cannot decode command version: %w", err)
	} else if v != CommandVersion {
		return failf("client requested unsupported version: %d", v)
	}

	if un, err = dec.DecodeString(); err != nil {
		return failf("cannot decode requested username: %w", err)
	}

	if v, err := dec.DecodeString(); err != nil {
		return failf("cannot decode configuration key: %w", err)
	} else if err = ck.UnmarshalText([]byte(v)); err != nil {
		return failf("cannot decode configuration key: %w", err)
	}

	if client, err = dec.DecodeString(); err != nil {
		return failf("cannot decode client info: %w", err)
	}

	return un, ck, client, nil
}

func WriteCommandHeader(un string, ck ConfigurationKey, client string, to io.Writer) error {
	fail := func(err error) error {
		return err
	}
	failf := func(message string, args ...any) error {
		return fail(fmt.Errorf(message, args...))
	}

	if n, err := to.Write([]byte(CommandMagicMarker)); err != nil {
		return failf("cannot write magic marker: %w", err)
	} else if n != len(CommandMagicMarker) {
		return failf("cannot write magic marker: should write %d; but only %d was written", len(CommandMagicMarker), n)
	}

	enc := msgpack.NewEncoder(to)

	if err := enc.EncodeUint16(CommandVersion); err != nil {
		return failf("cannot encode command version: %w", err)
	}

	if err := enc.EncodeString(un); err != nil {
		return failf("cannot encode requested username: %w", err)
	}

	if err := enc.EncodeString(ck.String()); err != nil {
		return failf("cannot encode configuration key: %w", err)
	}

	if err := enc.EncodeString(client); err != nil {
		return failf("cannot encode client info: %w", err)
	}

	return nil
}

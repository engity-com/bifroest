//go:build unix

package user

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

var (
	etcColonFileSeparator = []byte(":")
)

type etcColonEntryValue[T any] interface {
	*T
	decode(line [][]byte, allowBadName bool) error
	encode(allowBadName bool) ([][]byte, error)
}

type etcColonEntry[T any, PT etcColonEntryValue[T]] struct {
	entry   PT
	rawLine []byte
}

func (this *etcColonEntry[T, PT]) decode(rawLine []byte, expectedNumberOfColons int, allowBadName, allowBadEntries bool) error {
	line := bytes.SplitN(rawLine, etcColonFileSeparator, expectedNumberOfColons+1)
	if len(line) == 1 && len(line[0]) == 0 {
		*this = etcColonEntry[T, PT]{}
		return nil
	}

	if len(line) != expectedNumberOfColons {
		if allowBadEntries {
			*this = etcColonEntry[T, PT]{nil, rawLine}
			return nil
		}
		return fmt.Errorf("illegal amount of columns; expected %d; but got: %d", expectedNumberOfColons, len(line))
	}
	var buf etcColonEntry[T, PT]
	buf.entry = new(T)
	if err := buf.entry.decode(line, allowBadName); err != nil {
		if allowBadEntries {
			*this = etcColonEntry[T, PT]{nil, rawLine}
			return nil
		}
		return err
	}

	*this = buf
	return nil
}

func (this *etcColonEntry[T, PT]) encode(allowBadName bool, to io.Writer) error {
	if entry := this.entry; entry != nil {
		return this.writeEntryAsColonLine(allowBadName, entry, to)
	}
	if rawLine := this.rawLine; len(rawLine) > 0 {
		return this.writeLine(this.rawLine, to)
	}
	return nil
}

func (this *etcColonEntry[T, PT]) writeLine(line []byte, to io.Writer) error {
	fullNewLine := append(line, '\n')
	if n, err := to.Write(fullNewLine); err != nil {
		return err
	} else if n != len(fullNewLine) {
		return io.ErrShortWrite
	}
	return nil
}

func (this *etcColonEntry[T, PT]) writeColonLineColumns(line [][]byte, to io.Writer) error {
	return this.writeLine(bytes.Join(line, etcColonFileSeparator), to)
}

func (this *etcColonEntry[T, PT]) writeEntryAsColonLine(allowBadName bool, entry PT, to io.Writer) error {
	line, err := entry.encode(allowBadName)
	if err != nil {
		return err
	}
	return this.writeColonLineColumns(line, to)
}

func (this *etcColonEntry[T, PT]) IsZero() bool {
	return this.entry == nil && len(this.rawLine) == 0
}

type etcColonEntries[T any, PT etcColonEntryValue[T]] []etcColonEntry[T, PT]

type etcUnixEntriesSource interface {
	io.Reader
	Name() string
}

func (this *etcColonEntries[T, PT]) decode(expectedNumberOfColons int, allowBadName, allowBadEntries bool, from etcUnixEntriesSource) error {
	rd := bufio.NewScanner(from)
	rd.Split(bufio.ScanLines)

	var bufs etcColonEntries[T, PT]
	var lineNum uint32
	for rd.Scan() {
		var entry etcColonEntry[T, PT]
		if err := entry.decode(rd.Bytes(), expectedNumberOfColons, allowBadName, allowBadEntries); err != nil {
			return fmt.Errorf("cannot parse entry at %s:%d: %w", from.Name(), lineNum, err)
		}
		bufs = append(bufs, entry)
		lineNum++
	}
	*this = bufs
	return nil
}

type etcUnixEntriesTarget interface {
	io.Writer
	Name() string
	Truncate(int64) error
}

func (this etcColonEntries[T, PT]) encode(allowBadName bool, to etcUnixEntriesTarget) error {
	var lineNum uint32

	fail := func(err error) error {
		return fmt.Errorf("cannot write at %v:%d: %w", to.Name(), lineNum, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	if err := to.Truncate(0); err != nil {
		return failf("cannot empty file before write: %w", err)
	}

	for _, e := range this {
		if err := e.encode(allowBadName, to); err != nil {
			return fail(err)
		}

		lineNum++
	}

	return nil
}

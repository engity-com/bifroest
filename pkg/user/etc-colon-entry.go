//go:build unix && !android

package user

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
)

var (
	etcColonFileSeparator = []byte(":")
)

type etcColonEntryValue[T any] interface {
	*T
	setLine(line [][]byte, allowBadName bool) error
	encodeLine(allowBadName bool) ([][]byte, error)
}

type etcColonEntry[T any, PT etcColonEntryValue[T]] struct {
	entry   PT
	rawLine []byte
}

func (this *etcColonEntry[T, PT]) read(rawLine []byte, expectedNumberOfColons int, allowBadName, allowBadLines bool) error {
	line := bytes.SplitN(rawLine, etcColonFileSeparator, expectedNumberOfColons+1)
	if len(line) == 1 && len(line[0]) == 0 {
		*this = etcColonEntry[T, PT]{}
		return nil
	}

	if len(line) != expectedNumberOfColons {
		if allowBadLines {
			*this = etcColonEntry[T, PT]{nil, rawLine}
			return nil
		}
		return fmt.Errorf("illegal amount of columns; expected %d; but got: %d", expectedNumberOfColons, len(line))
	}
	var buf etcColonEntry[T, PT]
	buf.entry = new(T)
	if err := buf.entry.setLine(line, allowBadName); err != nil {
		if allowBadLines {
			*this = etcColonEntry[T, PT]{nil, rawLine}
			return nil
		}
		return err
	}

	*this = buf
	return nil
}

func (this *etcColonEntry[T, PT]) write(allowBadName bool, to io.Writer) error {
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
	return this.writeLine(bytes.Join(line, colonCommaFileSeparator), to)
}

func (this *etcColonEntry[T, PT]) writeEntryAsColonLine(allowBadName bool, entry PT, to io.Writer) error {
	line, err := entry.encodeLine(allowBadName)
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

func (this *etcColonEntries[T, PT]) readFrom(ctx context.Context, expectedNumberOfColons int, allowBadName, skipBadLine bool, from etcUnixEntriesSource) error {
	rd := bufio.NewScanner(from)
	rd.Split(bufio.ScanLines)

	var bufs etcColonEntries[T, PT]
	var lineNum uint32
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("cannot parse entry at %s:%d: %w", from.Name(), lineNum, err)
	}
	for rd.Scan() {
		var entry etcColonEntry[T, PT]
		if err := entry.read(rd.Bytes(), expectedNumberOfColons, allowBadName, skipBadLine); err != nil {
			return fmt.Errorf("cannot parse entry at %s:%d: %w", from.Name(), lineNum, err)
		}
		bufs = append(bufs, entry)
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("cannot parse entry at %s:%d: %w", from.Name(), lineNum, err)
		}
	}
	*this = bufs
	return nil
}

type etcUnixEntriesTarget interface {
	io.Writer
	Name() string
	Truncate(int64) error
}

func (this etcColonEntries[T, PT]) writeTo(ctx context.Context, allowBadName bool, to etcUnixEntriesTarget) error {
	var lineNum uint32

	fail := func(err error) error {
		return fmt.Errorf("cannot write at %q:%d: %w", to.Name(), lineNum, err)
	}
	failf := func(msg string, args ...any) error {
		return fail(fmt.Errorf(msg, args...))
	}

	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := to.Truncate(0); err != nil {
		return failf("cannot empty file before write: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	for i, e := range this {
		if err := e.write(allowBadName, to); err != nil {
			return failf("cannot write entry #%d: %w", i, err)
		}

		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		lineNum++
	}

	return nil
}

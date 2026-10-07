package common

import (
	"context"
	"io"
)

var (
	stdStreamsKey = struct{ stdStreams string }{stdStreams: "cli.stdStreams"}
)

type stdStreams struct {
	stdin  io.Reader
	stdout io.Writer
}

func ContextWithStdInOut(in context.Context, stdin io.Reader, stdout io.Writer) context.Context {
	return context.WithValue(in, stdStreamsKey, stdStreams{stdin, stdout})
}

func StdInOutOfContext(ctx context.Context) (io.Reader, io.Writer) {
	vv, ok := ctx.Value(stdStreamsKey).(stdStreams)
	if ok {
		return vv.stdin, vv.stdout
	}
	return nil, nil
}

func StdinOfContext(ctx context.Context) io.Reader {
	v, _ := StdInOutOfContext(ctx)
	return v
}

func StdoutOfContext(ctx context.Context) io.Writer {
	_, v := StdInOutOfContext(ctx)
	return v
}

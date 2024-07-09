package core

import (
	"errors"
	"fmt"
	"github.com/echocat/slf4g/level"
	"github.com/vmihailenco/msgpack/v5"
	"io"
	"os"
	"sync"
)

type CommandType uint8

const (
	CommandTypeLog CommandType = iota
	CommandTypeInfo
	CommandTypeSuccessResult
	CommandTypeFailedResult
)

func NewCommandSender(out io.Writer) *CommandSender {
	if out == nil {
		out = os.Stdout
	}
	return &CommandSender{
		encoder: msgpack.NewEncoder(out),
	}
}

type CommandSender struct {
	encoder *msgpack.Encoder
	mutex   sync.Mutex
}

func (this *CommandSender) Logf(l level.Level, message string, args ...any) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if err := this.writeCallType(CommandTypeLog); err != nil {
		return err
	}
	if err := this.encoder.EncodeUint16(uint16(l)); err != nil {
		return fmt.Errorf("cannot encode log level %v: %w", l, err)
	}
	msg := fmt.Sprintf(message, args...)
	if err := this.encoder.EncodeString(msg); err != nil {
		return fmt.Errorf("cannot encode log message %q: %w", msg, err)
	}

	return nil
}

func (this *CommandSender) MustLogf(l level.Level, message string, args ...any) {
	if err := this.Logf(l, message, args...); err != nil {
		panic(err)
	}
}

func (this *CommandSender) Infof(message string, args ...any) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if err := this.writeCallType(CommandTypeInfo); err != nil {
		return err
	}
	msg := fmt.Sprintf(message, args...)
	if err := this.encoder.EncodeString(msg); err != nil {
		return fmt.Errorf("cannot encode info message %q: %w", msg, err)
	}
	return nil
}

func (this *CommandSender) MustInfof(message string, args ...any) {
	if err := this.Infof(message, args...); err != nil {
		panic(err)
	}
}

func (this *CommandSender) SuccessResult(r Result, localUser string, localUid uint64, localGroup string, localGid uint64) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if err := this.writeCallType(CommandTypeSuccessResult); err != nil {
		return err
	}
	if err := this.encoder.EncodeUint8(uint8(r)); err != nil {
		return fmt.Errorf("cannot encode result %v: %w", r, err)
	}
	if err := this.encoder.EncodeString(localUser); err != nil {
		return fmt.Errorf("cannot encode local user %q: %w", localUser, err)
	}
	if err := this.encoder.EncodeUint64(localUid); err != nil {
		return fmt.Errorf("cannot encode local UID %d: %w", localUid, err)
	}
	if err := this.encoder.EncodeString(localGroup); err != nil {
		return fmt.Errorf("cannot encode local group %q: %w", localGroup, err)
	}
	if err := this.encoder.EncodeUint64(localGid); err != nil {
		return fmt.Errorf("cannot encode local GID %d: %w", localUid, err)
	}
	return nil
}

func (this *CommandSender) FailedResult(r Result, cause error) error {
	return this.FailedResultf(r, nil, "%v", cause)
}

func (this *CommandSender) FailedResultf(r Result, cause error, message string, args ...any) error {
	this.mutex.Lock()
	defer this.mutex.Unlock()

	if err := this.writeCallType(CommandTypeFailedResult); err != nil {
		return err
	}

	if err := this.encoder.EncodeUint8(uint8(r)); err != nil {
		return fmt.Errorf("cannot encode result %v: %w", r, err)
	}

	if cause != nil {
		message = message + ": %v"
		args = append(args, cause)
	}
	msg := fmt.Sprintf(message, args...)
	if err := this.encoder.EncodeString(msg); err != nil {
		return fmt.Errorf("cannot encode failed result %q: %w", msg, err)
	}
	return nil
}

func (this *CommandSender) writeCallType(v CommandType) error {
	if err := this.encoder.EncodeUint8(uint8(v)); err != nil {
		return fmt.Errorf("cannot encode call type %v: %w", v, err)
	}
	return nil
}

type CommandReceiver struct {
	OnLog           func(l level.Level, message string) error
	OnInfo          func(message string) error
	OnSuccessResult func(r Result, localUser string, localUid uint64, localGroup string, localGid uint64) (Result, error)
	OnFailedResult  func(r Result, message string) (Result, error)
}

func (this *CommandReceiver) Run(reader io.Reader) (Result, error) {
	result := ResultIgnore

	fail := func(err error) (Result, error) {
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		return ResultSystemErr, err
	}

	if reader == nil {
		reader = os.Stdin
	}

	decoder := msgpack.NewDecoder(reader)
	for {
		t, err := this.readCallType(decoder)
		if err != nil {
			return fail(err)
		}

		switch t {
		case CommandTypeLog:
			err = this.handleLog(decoder)
		case CommandTypeInfo:
			err = this.handleInfo(decoder)
		case CommandTypeSuccessResult:
			return this.handleSuccessResult(decoder)
		case CommandTypeFailedResult:
			return this.handleFailedResult(decoder)
		default:
			return fail(fmt.Errorf("illegal message call type received: %d", t))
		}
		if err != nil {
			return fail(err)
		}
	}
}

func (this *CommandReceiver) readCallType(from *msgpack.Decoder) (CommandType, error) {
	raw, err := from.DecodeUint8()
	if err != nil {
		return 0, fmt.Errorf("cannot decode error code from call message: %w", err)
	}
	return CommandType(raw), nil
}

func (this *CommandReceiver) handleLog(from *msgpack.Decoder) error {
	failf := func(message string, args ...any) error {
		return fmt.Errorf(message, args...)
	}

	l, err := from.DecodeUint16()
	if err != nil {
		return failf("cannot decode priority of syslog message: %w", err)
	}

	message, err := from.DecodeString()
	if err != nil {
		return failf("cannot decode message of syslog message: %w", err)
	}

	return this.OnLog(level.Level(l), message)
}

func (this *CommandReceiver) handleInfo(from *msgpack.Decoder) error {
	failf := func(message string, args ...any) error {
		return fmt.Errorf(message, args...)
	}

	message, err := from.DecodeString()
	if err != nil {
		return failf("cannot decode message of info message: %w", err)
	}

	return this.OnInfo(message)
}

func (this *CommandReceiver) handleSuccessResult(from *msgpack.Decoder) (Result, error) {
	failf := func(message string, args ...any) (Result, error) {
		return ResultSystemErr, fmt.Errorf(message, args...)
	}

	r, err := from.DecodeUint8()
	if err != nil {
		return failf("cannot decode result of success result message: %w", err)
	}
	localUser, err := from.DecodeString()
	if err != nil {
		return failf("cannot decode local user of success result message: %w", err)
	}
	localUid, err := from.DecodeUint64()
	if err != nil {
		return failf("cannot decode local UID of success result message: %w", err)
	}
	localGroup, err := from.DecodeString()
	if err != nil {
		return failf("cannot decode local group of success result message: %w", err)
	}
	localGid, err := from.DecodeUint64()
	if err != nil {
		return failf("cannot decode local GID of success result message: %w", err)
	}

	if result, err := this.OnSuccessResult(Result(r), localUser, localUid, localGroup, localGid); err != nil {
		return ResultSystemErr, err
	} else {
		return result, nil
	}
}

func (this *CommandReceiver) handleFailedResult(from *msgpack.Decoder) (Result, error) {
	failf := func(message string, args ...any) (Result, error) {
		return ResultSystemErr, fmt.Errorf(message, args...)
	}

	r, err := from.DecodeUint8()
	if err != nil {
		return failf("cannot decode result of failed result message: %w", err)
	}
	message, err := from.DecodeString()
	if err != nil {
		return failf("cannot decode message of success failed message: %w", err)
	}

	if result, err := this.OnFailedResult(Result(r), message); err != nil {
		return ResultSystemErr, err
	} else {
		return result, nil
	}
}

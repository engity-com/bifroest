package management

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// PlayAsciicast replays an already verified asciicast v3 stream. Verification
// and the explicit --with-sensitive decision belong to the caller.
func PlayAsciicast(ctx context.Context, source io.Reader, output io.Writer, speed float64) error {
	if speed <= 0 || speed > 100 {
		return fmt.Errorf("--speed must be greater than zero and at most 100")
	}
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return fmt.Errorf("recording is empty")
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(scanner.Bytes(), &header); err != nil {
		return fmt.Errorf("invalid asciicast header: %w", err)
	}
	if header.Version != 3 {
		return fmt.Errorf("unsupported asciicast version %d", header.Version)
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		var event []json.RawMessage
		if err := json.Unmarshal([]byte(line), &event); err != nil || len(event) != 3 {
			return fmt.Errorf("invalid asciicast event: %v", err)
		}
		var elapsed float64
		var kind, value string
		if err := json.Unmarshal(event[0], &elapsed); err != nil || elapsed < 0 || elapsed > 365*24*60*60 {
			return fmt.Errorf("invalid asciicast event time")
		}
		if err := json.Unmarshal(event[1], &kind); err != nil {
			return err
		}
		if err := json.Unmarshal(event[2], &value); err != nil {
			return err
		}
		if delay := time.Duration(elapsed / speed * float64(time.Second)); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
		if kind == "o" {
			if _, err := io.WriteString(output, value); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

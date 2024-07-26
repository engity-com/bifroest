package cmd

import (
	"testing"
	"time"
)

func Test(t *testing.T) {
	firstTick := true
	timer := time.AfterFunc(-1*time.Hour, func() {
		if firstTick {
			firstTick = false
			return
		}
		t.Logf("Tick: %v", time.Now())
	})
	t.Logf("Doh!: %v", time.Now())

	time.Sleep(100 * time.Millisecond)

	timer.Stop()
	timer.Reset(100 * time.Millisecond)

	time.Sleep(2 * time.Second)
}

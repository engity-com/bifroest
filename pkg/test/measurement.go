//go:build !windows

package test

import "time"

type measurementStart struct{ time.Time }

func startMeasurement() measurementStart { return measurementStart{time.Now()} }

func (start measurementStart) seconds() float64 { return time.Since(start.Time).Seconds() }

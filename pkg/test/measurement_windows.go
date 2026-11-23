package test

import (
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	measurementKernel32  = windows.NewLazySystemDLL("kernel32.dll")
	performanceCounter   = measurementKernel32.NewProc("QueryPerformanceCounter")
	performanceFrequency = performanceTicks(measurementKernel32.NewProc("QueryPerformanceFrequency"))
)

// Go's Windows time.Time monotonic readings can share a coarse clock tick.
// QPC measures short discovery/filter/error paths without changing any execution
// deadline, sleeping, or substituting an artificial minimum duration.
type measurementStart int64

func startMeasurement() measurementStart {
	return measurementStart(performanceTicks(performanceCounter))
}

func (start measurementStart) seconds() float64 {
	return performanceSeconds(int64(start), performanceTicks(performanceCounter), performanceFrequency)
}

func performanceTicks(proc *windows.LazyProc) int64 {
	var ticks int64
	if ok, _, _ := proc.Call(uintptr(unsafe.Pointer(&ticks))); ok == 0 {
		return -1
	}
	return ticks
}

func performanceSeconds(start, end, frequency int64) float64 {
	if start < 0 || end < start || frequency <= 0 {
		// Both JSON and JUnit reject NaN rather than publishing a false timing.
		return math.NaN()
	}
	// Subtract integer ticks before conversion to retain short intervals even
	// when the machine has been running for a long time.
	return float64(end-start) / float64(frequency)
}

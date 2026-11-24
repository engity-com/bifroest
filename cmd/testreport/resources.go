package main

import "os"

func measureResources(state *os.ProcessState) *resources {
	if state == nil {
		return nil
	}
	r := &resources{CPUScope: "OS ProcessState accounting for the command; inclusion of waited descendants is OS-dependent, not sampled process-tree utilization"}
	if user := state.UserTime(); user >= 0 {
		r.UserCPUSeconds = seconds(user.Seconds())
	}
	if system := state.SystemTime(); system >= 0 {
		r.SystemCPUSeconds = seconds(system.Seconds())
	}
	r.MaxRSSBytes, r.MaxRSSScope = rss(state)
	return r
}

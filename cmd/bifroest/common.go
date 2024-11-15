package main

import goos "os"

func workingDirectory() string {
	v, err := goos.Getwd()
	if err == nil {
		return v
	}
	return "/"
}

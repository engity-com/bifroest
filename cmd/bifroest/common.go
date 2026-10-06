package main

import (
	goos "os"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func loadManagementConfiguration(path string) (*configuration.Configuration, error) {
	if path == "" {
		path = defaultConfigurationRef
	}
	var ref configuration.Ref
	if err := ref.Set(path); err != nil {
		return nil, err
	}
	return ref.Get(), nil
}

func workingDirectory() string {
	v, err := goos.Getwd()
	if err == nil {
		return v
	}
	return "/"
}

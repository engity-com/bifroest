package common

import (
	os2 "os"

	"github.com/engity-com/bifroest/pkg/configuration"
)

func LoadManagementConfiguration(path string) (*configuration.Configuration, error) {
	if path == "" {
		path = configuration.DefaultRef
	}
	var ref configuration.Ref
	if err := ref.Set(path); err != nil {
		return nil, err
	}
	return ref.Get(), nil
}

func WorkingDirectory() string {
	v, err := os2.Getwd()
	if err == nil {
		return v
	}
	return "/"
}

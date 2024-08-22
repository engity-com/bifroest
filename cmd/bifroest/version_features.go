package main

import (
	"fmt"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto/unix/password"
)

var (
	featuresV = &features{}
)

type features struct{}

func (this *features) ForEach(consumer func(common.VersionFeatureCategory)) {
	consumer(&featureCategory{"authorizations", configuration.GetSupportedAuthorizationVs})
	consumer(&featureCategory{"environments", configuration.GetSupportedEnvironmentVs})
	consumer(&featureCategory{"sessions", configuration.GetSupportedSessionVs})
	consumer(&featureCategory{"pam", func() []string {
		return []string{fmt.Sprint(configuration.IsPamSupported())}
	}})
	consumer(&featureCategory{"password-crypt", password.GetSupportedCrypts})
}

type featureCategory struct {
	name   string
	getter func() []string
}

func (this *featureCategory) Name() string {
	return this.name
}

func (this *featureCategory) ForEach(consumer func(common.VersionFeature)) {
	for _, v := range this.getter() {
		consumer(feature(v))
	}
}

type feature string

func (this feature) Name() string {
	return string(this)
}

package main

import (
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/crypto/unix/password"
	"github.com/engity-com/bifroest/pkg/sys"
)

var (
	featuresV = &features{}
)

type features struct{}

func (this *features) ForEach(consumer func(sys.VersionFeatureCategory)) {
	consumer(&featureCategory{"authorization", configuration.GetSupportedAuthorizationFeatureFlags})
	consumer(&featureCategory{"environment", configuration.GetSupportedEnvironmentFeatureFlags})
	consumer(&featureCategory{"session", configuration.GetSupportedSessionFeatureFlags})
	consumer(&featureCategory{"password-crypt", password.GetSupportedFeatureFlags})
}

type featureCategory struct {
	name   string
	getter func() []string
}

func (this *featureCategory) Name() string {
	return this.name
}

func (this *featureCategory) ForEach(consumer func(sys.VersionFeature)) {
	for _, v := range this.getter() {
		consumer(feature(v))
	}
}

type feature string

func (this feature) Name() string {
	return string(this)
}

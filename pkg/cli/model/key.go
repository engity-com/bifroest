package model

import "github.com/engity-com/bifroest/pkg/configuration"

type KeyExportRequest struct {
	Kind          string
	Flow          configuration.FlowName
	IdentityIndex uint
	Address       string
	Comment       string
}

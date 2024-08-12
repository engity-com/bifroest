package authorization

import (
	"encoding/json"
	"github.com/engity-com/bifroest/pkg/common"
	"github.com/engity-com/bifroest/pkg/configuration"
	"github.com/engity-com/bifroest/pkg/sys"
	"github.com/engity-com/bifroest/pkg/user"
)

type Local struct {
	*user.User
	remote  common.Remote
	envVars sys.EnvVars
	flow    configuration.FlowName
}

func (this *Local) Remote() common.Remote {
	return this.remote
}

func (this *Local) IsAuthorized() bool {
	return true
}

func (this *Local) EnvVars() sys.EnvVars {
	return this.envVars
}

func (this *Local) Flow() configuration.FlowName {
	return this.flow
}

func (this *Local) MarshalToken() ([]byte, error) {
	var buf localToken
	buf.User.Name = this.User.Name
	buf.User.Uid = common.P(this.User.Uid)
	buf.EnvVars = this.envVars
	return json.Marshal(buf)
}

type localToken struct {
	User    localTokenUser `json:"user"`
	EnvVars sys.EnvVars    `json:"envVars"`
}

type localTokenUser struct {
	Name string   `json:"name,omitempty"`
	Uid  *user.Id `json:"uid,omitempty"`
}

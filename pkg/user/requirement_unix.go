//go:build unix

package user

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

type Requirement struct {
	Name        string            `yaml:"name,omitempty"`
	DisplayName string            `yaml:"displayName,omitempty"`
	Uid         *Id               `yaml:"uid,omitempty"`
	Group       GroupRequirement  `yaml:"group,omitempty"`
	Groups      GroupRequirements `yaml:"groups,omitempty"`
	Shell       string            `yaml:"shell,omitempty"`
	HomeDir     string            `yaml:"homeDir,omitempty"`
	Skel        string            `yaml:"skel,omitempty"`
}

func (this Requirement) Clone() Requirement {
	return Requirement{
		strings.Clone(this.Name),
		strings.Clone(this.DisplayName),
		this.Uid,
		this.Group.Clone(),
		this.Groups.Clone(),
		strings.Clone(this.Shell),
		strings.Clone(this.HomeDir),
		strings.Clone(this.Skel),
	}
}

func (this Requirement) OrDefaults() Requirement {
	result := this.Clone()
	if result.Name == "" && result.Uid != nil {
		result.Name = fmt.Sprintf("user-%d", *result.Uid)
	}
	if result.HomeDir == "" && result.Name != "" {
		result.HomeDir = filepath.Join("/home", result.Name)
	}
	if result.Group.IsZero() {
		result.Group = GroupRequirement{Name: strings.Clone(this.Name)}
	}
	if result.Groups.IsZero() {
		result.Groups = GroupRequirements{{Name: defaultGroupName}}
	}
	return result
}

func (this Requirement) IsZero() bool {
	return len(this.Name) == 0 &&
		len(this.DisplayName) == 0 &&
		this.Uid == nil &&
		this.Group.IsZero() &&
		this.Groups.IsZero() &&
		len(this.Shell) == 0 &&
		len(this.HomeDir) == 0 &&
		len(this.Skel) == 0
}

func (this Requirement) IsEqualTo(other any) bool {
	if other == nil {
		return false
	}
	switch v := other.(type) {
	case Requirement:
		return this.isEqualTo(&v)
	case *Requirement:
		return this.isEqualTo(v)
	default:
		return false
	}
}

func (this Requirement) isEqualTo(other *Requirement) bool {
	return this.Name == other.Name &&
		this.DisplayName == other.DisplayName &&
		IdEqualsP(this.Uid, other.Uid) &&
		this.Group.IsEqualTo(&other.Group) &&
		this.Groups.IsEqualTo(&other.Groups) &&
		this.Shell == other.Shell &&
		this.HomeDir == other.HomeDir &&
		this.Skel == other.Skel
}

func (this Requirement) doesFulfilRef(target *etcPasswdRef) bool {
	if target == nil {
		return false
	}
	uid := Id(target.uid)
	return this.Name == string(target.etcPasswdEntry.name) &&
		this.DisplayName == string(target.etcPasswdEntry.geocs) &&
		IdEqualsP(this.Uid, &uid) &&
		this.Shell == string(target.etcPasswdEntry.shell) &&
		this.HomeDir == string(target.etcPasswdEntry.homeDir)
}

func (this Requirement) String() string {
	if name := this.Name; len(name) > 0 {
		if uid := this.Uid; uid != nil {
			return fmt.Sprintf("%d(%s)", uid, name)
		} else {
			return strings.Clone(name)
		}
	} else if uid := this.Uid; uid != nil {
		return strconv.FormatUint(uint64(*uid), 10)
	} else {
		return "<empty>"
	}
}

func (this Requirement) name() string {
	name := strings.Clone(this.Name)
	if len(name) > 0 {
		return name
	}
	if uid := this.Uid; uid != nil {
		return fmt.Sprintf("user-%d", uid)
	}
	return ""
}

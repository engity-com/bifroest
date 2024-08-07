package user

import "github.com/engity-com/bifroest/pkg/common"

type etcColonRepositoryHandles struct {
	passwd etcColonRepositoryHandle[etcPasswdEntry, *etcPasswdEntry]
	group  etcColonRepositoryHandle[etcGroupEntry, *etcGroupEntry]
	shadow etcColonRepositoryHandle[etcShadowEntry, *etcShadowEntry]
}

func (this *etcColonRepositoryHandles) init(owner *EtcColonRepository) error {
	success := false
	defer common.DoOnFailureIgnore(&success, this.close)

	if err := this.passwd.init(owner.PasswdFilename, DefaultEtcPasswd, etcPasswdColons, owner); err != nil {
		return err
	}
	if err := this.group.init(owner.GroupFilename, DefaultEtcGroup, etcGroupColons, owner); err != nil {
		return err
	}
	if err := this.shadow.init(owner.ShadowFilename, DefaultEtcShadow, etcShadowColons, owner); err != nil {
		return err
	}

	success = true
	return nil
}

func (this *etcColonRepositoryHandles) open(rw bool) (_ *openedEtcColonRepositoryHandles, rErr error) {
	success := false

	var result openedEtcColonRepositoryHandles
	var err error

	if result.passwd, err = this.passwd.openFile(rw); err != nil {
		return nil, err
	}
	defer common.DoOnFailureIgnore(&success, this.passwd.close)

	if result.group, err = this.group.openFile(rw); err != nil {
		return nil, err
	}
	defer common.DoOnFailureIgnore(&success, this.group.close)

	if result.shadow, err = this.shadow.openFile(rw); err != nil {
		return nil, err
	}
	defer common.DoOnFailureIgnore(&success, this.shadow.close)

	success = true
	return &result, nil
}

func (this *etcColonRepositoryHandles) close() (rErr error) {
	defer common.KeepError(&rErr, this.passwd.close)
	defer common.KeepError(&rErr, this.group.close)
	defer common.KeepError(&rErr, this.shadow.close)

	return nil
}

type openedEtcColonRepositoryHandles struct {
	passwd *openedEtcColonRepositoryHandle[etcPasswdEntry, *etcPasswdEntry]
	group  *openedEtcColonRepositoryHandle[etcGroupEntry, *etcGroupEntry]
	shadow *openedEtcColonRepositoryHandle[etcShadowEntry, *etcShadowEntry]
}

func (this *openedEtcColonRepositoryHandles) load() error {
	if err := this.passwd.load(); err != nil {
		return err
	}
	if err := this.group.load(); err != nil {
		return err
	}
	if err := this.shadow.load(); err != nil {
		return err
	}

	return nil
}

func (this *openedEtcColonRepositoryHandles) save() error {
	if err := this.passwd.save(); err != nil {
		return err
	}
	if err := this.group.save(); err != nil {
		return err
	}
	if err := this.shadow.save(); err != nil {
		return err
	}

	return nil
}

func (this *openedEtcColonRepositoryHandles) close() (rErr error) {
	defer common.KeepError(&rErr, this.passwd.close)
	defer common.KeepError(&rErr, this.group.close)
	defer common.KeepError(&rErr, this.shadow.close)

	return nil
}

//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/engity-com/bifroest/test/nanoserver/browserfixture"
)

const browserPasswordPath = `C:\smoke\browser-password.txt`

func prepareRememberBrowserGroup(fixture *browserfixture.Fixture) error {
	if err := ownedRememberAccount(*fixture); err != nil {
		return err
	}
	fixture.RememberGroup = "bifrg" + strings.TrimPrefix(fixture.User, "bif")
	name, err := windows.UTF16PtrFromString(fixture.RememberGroup)
	if err != nil {
		return err
	}
	info := struct{ Name *uint16 }{name}
	var parameter uint32
	add := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetLocalGroupAdd")
	if err := add.Find(); err != nil {
		return err
	}
	status, _, _ := add.Call(0, 0, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(name)
	if status != 0 {
		return fmt.Errorf("create owned remember group: nativeStatus=%d", uint32(status))
	}
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	sid, domain, kind, err := windows.LookupSID("", host+`\`+fixture.RememberGroup)
	if err != nil {
		return err
	}
	if sid == nil || !sid.IsValid() || kind != windows.SidTypeAlias || !strings.EqualFold(host, domain) {
		return fmt.Errorf("owned remember group identity unavailable; retain only for container teardown")
	}
	fixture.RememberGroupSID = sid.String()
	return setRememberBrowserMembership(*fixture, true)
}

func setRememberBrowserMembership(fixture browserfixture.Fixture, add bool) error {
	if err := ownedRememberAccount(fixture); err != nil {
		return err
	}
	if fixture.RememberGroup == "" || fixture.RememberGroupSID == "" {
		return fmt.Errorf("owned remember group binding missing")
	}
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	sid, domain, kind, err := windows.LookupSID("", host+`\`+fixture.RememberGroup)
	if err != nil {
		return err
	}
	if sid == nil || sid.String() != fixture.RememberGroupSID || kind != windows.SidTypeAlias || !strings.EqualFold(host, domain) {
		return fmt.Errorf("owned remember group changed SID")
	}
	name, err := windows.UTF16PtrFromString(fixture.RememberGroup)
	if err != nil {
		return err
	}
	member, err := windows.StringToSid(fixture.SID)
	if err != nil {
		return err
	}
	info := struct{ SID *windows.SID }{member}
	operation := "NetLocalGroupDelMembers"
	if add {
		operation = "NetLocalGroupAddMembers"
	}
	procedure := windows.NewLazySystemDLL("netapi32.dll").NewProc(operation)
	if err := procedure.Find(); err != nil {
		return err
	}
	status, _, _ := procedure.Call(0, uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&info)), 1)
	runtime.KeepAlive(name)
	runtime.KeepAlive(member)
	if status != 0 {
		return fmt.Errorf("update owned remember group membership: nativeStatus=%d", uint32(status))
	}
	return nil
}

func toggleRememberBrowserGroup(add bool) error {
	fixture, err := readBrowserFixture()
	if err != nil {
		return err
	}
	return setRememberBrowserMembership(fixture, add)
}

func ownedRememberAccount(fixture browserfixture.Fixture) error {
	if err := requireBrowserContainer(); err != nil {
		return err
	}
	if !fixture.PasswordResume {
		return fmt.Errorf("password-resume fixture is not enabled")
	}
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	sid, domain, kind, err := windows.LookupSID("", host+`\`+fixture.User)
	if err != nil {
		return err
	}
	if sid == nil || !sid.IsValid() || sid.String() != fixture.SID || kind != windows.SidTypeUser || !strings.EqualFold(host, domain) {
		return fmt.Errorf("owned password-resume account identity changed")
	}
	return nil
}

func prepareBrowserPassword(fixture browserfixture.Fixture) error {
	if err := ownedRememberAccount(fixture); err != nil {
		return err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	password := "R3member!" + hex.EncodeToString(random[:]) + "Z"
	clear(random[:])
	name, err := windows.UTF16PtrFromString(fixture.User)
	if err != nil {
		return err
	}
	units, err := windows.UTF16FromString(password)
	if err != nil {
		return err
	}
	defer clear(units)
	info := struct{ Password *uint16 }{&units[0]}
	var parameter uint32
	set := windows.NewLazySystemDLL("netapi32.dll").NewProc("NetUserSetInfo")
	if err := set.Find(); err != nil {
		return err
	}
	status, _, _ := set.Call(0, uintptr(unsafe.Pointer(name)), 1003, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(name)
	runtime.KeepAlive(units)
	if status != 0 {
		return fmt.Errorf("set own browser fixture password: nativeStatus=%d parameter=%d", uint32(status), parameter)
	}
	if err := ownedRememberAccount(fixture); err != nil {
		return err
	}
	// Test-only primary credential: protected container file, copied only into
	// an owned host temp file. Never fixture JSON, logs, session or browser storage.
	raw := []byte(password)
	defer clear(raw)
	return writeBrowserPrivateFile(browserPasswordPath, raw)
}

func restartRememberBrowserContainer() (resultErr error) {
	fixture, err := readBrowserFixture()
	if err != nil {
		return err
	}
	if err := ownedRememberAccount(fixture); err != nil {
		return err
	}
	marker := filepath.Join(fixture.Root, "owned-restart.marker")
	if err := os.WriteFile(marker, []byte("owned browser restart"), 0600); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.Remove(marker)) }()
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, manager.Disconnect()) }()
	service, err := manager.OpenService(fixture.Service)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, service.Close()) }()
	if _, err := service.Control(svc.Stop); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		state, err := service.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Stopped {
			if state.Win32ExitCode != 0 || state.ServiceSpecificExitCode != 0 {
				return fmt.Errorf("owned service did not stop cleanly")
			}
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("owned service did not stop within fixture deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := service.Start(); err != nil {
		return err
	}
	deadline = time.Now().Add(15 * time.Second)
	for {
		state, err := service.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Running {
			return nil
		}
		if state.State == svc.Stopped && (state.Win32ExitCode != 0 || state.ServiceSpecificExitCode != 0) {
			return fmt.Errorf("owned restarted service failed")
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("owned service did not restart within fixture deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func toggleRememberBrowserAccount(disabled bool) (resultErr error) {
	fixture, err := readBrowserFixture()
	if err != nil {
		return err
	}
	if err := ownedRememberAccount(fixture); err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(fixture.User)
	if err != nil {
		return err
	}
	library := windows.NewLazySystemDLL("netapi32.dll")
	get, set, free := library.NewProc("NetUserGetInfo"), library.NewProc("NetUserSetInfo"), library.NewProc("NetApiBufferFree")
	for _, procedure := range []*windows.LazyProc{get, set, free} {
		if err := procedure.Find(); err != nil {
			return err
		}
	}
	var info *containerTestUserInfo
	status, _, _ := get.Call(0, uintptr(unsafe.Pointer(name)), 1, uintptr(unsafe.Pointer(&info)))
	runtime.KeepAlive(name)
	if info != nil {
		defer func() {
			code, _, _ := free.Call(uintptr(unsafe.Pointer(info)))
			if code != 0 {
				resultErr = errors.Join(resultErr, fmt.Errorf("free owned user flags: nativeStatus=%d", uint32(code)))
			}
		}()
	}
	if status != 0 || info == nil {
		return fmt.Errorf("read own account flags: nativeStatus=%d", uint32(status))
	}
	flags := info.Flags
	path := filepath.Join(fixture.Root, "owned-password-flags.json")
	if disabled {
		if flags&0x2 != 0 {
			return fmt.Errorf("owned account unexpectedly already disabled")
		}
		raw, _ := json.Marshal(struct {
			SID   string
			Flags uint32
		}{fixture.SID, flags})
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(raw)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return err
		}
		flags |= 0x2
	} else {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var original struct {
			SID   string
			Flags uint32
		}
		if json.Unmarshal(raw, &original) != nil || original.SID != fixture.SID {
			return fmt.Errorf("owned flags restoration identity unavailable")
		}
		flags = original.Flags
	}
	if err := ownedRememberAccount(fixture); err != nil {
		return err
	}
	var parameter uint32
	status, _, _ = set.Call(0, uintptr(unsafe.Pointer(name)), 1008, uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(name)
	if status != 0 {
		return fmt.Errorf("update own browser account flags: nativeStatus=%d parameter=%d", uint32(status), parameter)
	}
	var verified *containerTestUserInfo
	status, _, _ = get.Call(0, uintptr(unsafe.Pointer(name)), 1, uintptr(unsafe.Pointer(&verified)))
	runtime.KeepAlive(name)
	if verified != nil {
		defer func() {
			code, _, _ := free.Call(uintptr(unsafe.Pointer(verified)))
			if code != 0 {
				resultErr = errors.Join(resultErr, fmt.Errorf("free verified owned flags: nativeStatus=%d", uint32(code)))
			}
		}()
	}
	if status != 0 || verified == nil || verified.Flags != flags {
		return fmt.Errorf("owned account flags update/restore was not verified")
	}
	if err := ownedRememberAccount(fixture); err != nil {
		return err
	}
	if !disabled {
		return os.Remove(path)
	}
	return nil
}

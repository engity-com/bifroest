//go:build windows

package environment

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func localProfileTestToken(t *testing.T) windows.Token {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := token.Close(); err != nil {
			t.Errorf("close profile test token: %v", err)
		}
	})
	return token
}

func TestLocalProfileSafeInfoMissingPreservesNotExist(t *testing.T) {
	_, err := localProfileSafeInfo(filepath.Join(t.TempDir(), "not-created"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file must preserve not-exist identity: %v", err)
	}
}

func TestCopyLocalWindowsProfileTemplate(t *testing.T) {
	token := localProfileTestToken(t)
	root := t.TempDir()
	source, target := filepath.Join(root, "template"), filepath.Join(root, "profile")
	for _, dir := range []string{filepath.Join(source, "nested", "deep"), filepath.Join(source, "empty"), filepath.Join(target, "nested")} {
		if err := os.MkdirAll(dir, 0777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "deep", "settings.txt"), []byte("template"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep.txt"), []byte("existing"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := copyLocalWindowsProfileTemplate(source, target, token); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(target, "nested", "deep", "settings.txt"))
	if err != nil || string(data) != "template" {
		t.Fatalf("copied file: %q, %v", data, err)
	}
	if info, err := os.Stat(filepath.Join(target, "empty")); err != nil || !info.IsDir() {
		t.Fatalf("empty directory: %v, %v", info, err)
	}
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(target, "empty"), filepath.Join(target, "nested", "deep"), filepath.Join(target, "nested", "deep", "settings.txt")} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			t.Fatalf("owner of %q: %v", path, err)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil || !owner.Equals(user.User.Sid) {
			t.Fatalf("owner of %q: %v, %v; want %v", path, owner, err, user.User.Sid)
		}
	}
	if data, err := os.ReadFile(filepath.Join(target, "keep.txt")); err != nil || string(data) != "existing" {
		t.Fatalf("existing file: %q, %v", data, err)
	}
	if err := copyLocalWindowsProfileTemplate(source, target, token); err == nil {
		t.Fatal("second copy did not reject existing file")
	}
}

func TestCopyLocalWindowsProfileTemplateCollision(t *testing.T) {
	token := localProfileTestToken(t)
	root := t.TempDir()
	source, target := filepath.Join(root, "template"), filepath.Join(root, "profile")
	for _, dir := range []string{source, target} {
		if err := os.Mkdir(dir, 0777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(source, "a-empty"), 0777); err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct{ name, dir, value string }{
		{"a-new.txt", source, "new"},
		{"z-conflict.txt", source, "source"},
		{"z-conflict.txt", target, "original"},
	} {
		if err := os.WriteFile(filepath.Join(file.dir, file.name), []byte(file.value), 0666); err != nil {
			t.Fatal(err)
		}
	}
	if err := copyLocalWindowsProfileTemplate(source, target, token); err == nil {
		t.Fatal("accepted existing destination file")
	}
	if data, err := os.ReadFile(filepath.Join(target, "z-conflict.txt")); err != nil || string(data) != "original" {
		t.Fatalf("collision changed existing file: %q, %v", data, err)
	}
	if _, err := os.Lstat(filepath.Join(target, "a-new.txt")); !os.IsNotExist(err) {
		t.Fatalf("wrote before collision check: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "a-empty")); !os.IsNotExist(err) {
		t.Fatalf("created directory before collision check: %v", err)
	}
}

func TestCopyLocalWindowsProfileTemplateNestedCollisionPreflight(t *testing.T) {
	token := localProfileTestToken(t)
	root := t.TempDir()
	source, target := filepath.Join(root, "template"), filepath.Join(root, "profile")
	for _, dir := range []string{filepath.Join(source, "nested", "deep"), target} {
		if err := os.MkdirAll(dir, 0777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "nested", "deep", "settings.txt"), []byte("template"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "a-new.txt"), []byte("new"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "NESTED"), []byte("existing"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := copyLocalWindowsProfileTemplate(source, target, token); err == nil {
		t.Fatal("accepted nested directory collision")
	}
	if _, err := os.Lstat(filepath.Join(target, "a-new.txt")); !os.IsNotExist(err) {
		t.Fatalf("wrote before collision check: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(target, "NESTED")); err != nil || string(data) != "existing" {
		t.Fatalf("collision changed existing file: %q, %v", data, err)
	}
}

func TestCopyLocalWindowsProfileTemplateOverlappingPaths(t *testing.T) {
	token := localProfileTestToken(t)
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0777); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{root, root}, {root, child}, {child, root}} {
		if err := copyLocalWindowsProfileTemplate(pair[0], pair[1], token); err == nil {
			t.Fatalf("accepted overlapping paths %q and %q", pair[0], pair[1])
		}
	}
}

func TestCopyLocalWindowsProfileTemplateReparsePoints(t *testing.T) {
	token := localProfileTestToken(t)
	for _, tc := range []struct {
		name     string
		link     func(string, string) error
		linkDir  bool
		location string
	}{
		{"source symlink", os.Symlink, false, "source"},
		{"destination symlink", os.Symlink, false, "destination"},
		{"destination ancestor symlink", os.Symlink, true, "ancestor"},
		{"source junction", junctionLocalProfileTest, true, "source"},
		{"destination junction", junctionLocalProfileTest, true, "nested"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			source, target := filepath.Join(root, "template"), filepath.Join(root, "profile")
			for _, dir := range []string{source, target} {
				if err := os.Mkdir(dir, 0777); err != nil {
					t.Fatal(err)
				}
			}
			external := filepath.Join(root, "external")
			if tc.linkDir {
				if err := os.Mkdir(external, 0777); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(external, []byte("outside"), 0666); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(source, "link")
			switch tc.location {
			case "destination":
				link = filepath.Join(target, "link")
				if err := os.WriteFile(filepath.Join(source, "link"), []byte("template"), 0666); err != nil {
					t.Fatal(err)
				}
			case "nested":
				link = filepath.Join(target, "nested")
				if err := os.Mkdir(filepath.Join(source, "nested"), 0777); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(source, "nested", "settings.txt"), []byte("template"), 0666); err != nil {
					t.Fatal(err)
				}
			case "ancestor":
				link = filepath.Join(root, "alias")
				target = filepath.Join(link, "profile")
				if err := os.Mkdir(filepath.Join(external, "profile"), 0777); err != nil {
					t.Fatal(err)
				}
			}
			if err := tc.link(external, link); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			if err := os.WriteFile(filepath.Join(source, "a-new.txt"), []byte("new"), 0666); err != nil {
				t.Fatal(err)
			}
			if err := copyLocalWindowsProfileTemplate(source, target, token); err == nil {
				t.Fatal("accepted reparse point")
			}
			if _, err := os.Lstat(filepath.Join(target, "a-new.txt")); !os.IsNotExist(err) {
				t.Fatalf("wrote before reparse point check: %v", err)
			}
		})
	}
}

func TestCopyLocalWindowsProfileTemplateUnrelatedReparsePoints(t *testing.T) {
	token := localProfileTestToken(t)
	for _, tc := range []struct {
		name string
		link func(string, string) error
	}{
		{"symlink", os.Symlink},
		{"junction", junctionLocalProfileTest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			source, target, external := filepath.Join(root, "template"), filepath.Join(root, "profile"), filepath.Join(root, "external")
			for _, dir := range []string{filepath.Join(source, "nested"), target, external} {
				if err := os.MkdirAll(dir, 0777); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(source, "nested", "settings.txt"), []byte("template"), 0666); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(external, "keep.txt"), []byte("outside"), 0666); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(target, "unrelated")
			if err := tc.link(external, link); err != nil {
				t.Skipf("link unavailable: %v", err)
			}
			if err := copyLocalWindowsProfileTemplate(source, target, token); err != nil {
				t.Fatal(err)
			}
			if data, err := os.ReadFile(filepath.Join(target, "nested", "settings.txt")); err != nil || string(data) != "template" {
				t.Fatalf("copied file: %q, %v", data, err)
			}
			if _, err := os.Lstat(link); err != nil {
				t.Fatalf("unrelated link: %v", err)
			}
			if data, err := os.ReadFile(filepath.Join(external, "keep.txt")); err != nil || string(data) != "outside" {
				t.Fatalf("external file: %q, %v", data, err)
			}
		})
	}
}

func TestCopyLocalWindowsProfileTemplateMissingSource(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "profile")
	if err := os.Mkdir(target, 0777); err != nil {
		t.Fatal(err)
	}
	if err := copyLocalWindowsProfileTemplate(filepath.Join(root, "missing"), target, localProfileTestToken(t)); err == nil {
		t.Fatal("accepted missing template directory")
	}
}

func TestCopyLocalWindowsProfileTemplateInvalidToken(t *testing.T) {
	root := t.TempDir()
	source, target := filepath.Join(root, "template"), filepath.Join(root, "profile")
	for _, path := range []string{source, target} {
		if err := os.Mkdir(path, 0777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "settings.txt"), []byte("private"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := copyLocalWindowsProfileTemplate(source, target, 0); err == nil {
		t.Fatal("accepted invalid impersonation token")
	}
	if _, err := os.Lstat(filepath.Join(target, "settings.txt")); !os.IsNotExist(err) {
		t.Fatalf("wrote with invalid token: %v", err)
	}
}

func junctionLocalProfileTest(oldname, newname string) error {
	return exec.Command("cmd", "/c", "mklink", "/J", newname, oldname).Run()
}

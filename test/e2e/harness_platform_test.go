//go:build e2e

package e2e_test

import "testing"

func TestE2ETargetForHost(t *testing.T) {
	tests := []struct {
		name         string
		hostOS       string
		hostArch     string
		wantGOOS     string
		wantGOARCH   string
		wantPlatform string
		wantError    bool
	}{
		{"Linux AMD64", "linux", "amd64", "linux", "amd64", "linux/amd64", false},
		{"Linux ARM64", "linux", "arm64", "linux", "arm64", "linux/arm64", false},
		{"Darwin AMD64", "darwin", "amd64", "linux", "amd64", "linux/amd64", false},
		{"Darwin ARM64", "darwin", "arm64", "linux", "arm64", "linux/arm64", false},
		{"Windows", "windows", "amd64", "", "", "", true},
		{"unsupported architecture", "darwin", "riscv64", "", "", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			goos, goarch, platform, err := e2eTargetForHost(test.hostOS, test.hostArch)
			if test.wantError {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if goos != test.wantGOOS || goarch != test.wantGOARCH || platform != test.wantPlatform {
				t.Fatalf("target: got %s/%s (%s), want %s/%s (%s)", goos, goarch, platform, test.wantGOOS, test.wantGOARCH, test.wantPlatform)
			}
		})
	}
}

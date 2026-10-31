package main

import (
	"fmt"
	"path/filepath"

	"github.com/engity-com/bifroest/test/nanoserver/browserfixture"
)

func browserConfiguration(root, user, sid string) string {
	return browserConfigurationWithPassword(root, user, sid, false)
}

func browserConfigurationWithPassword(root, user, sid string, passwordResume bool, groupSID ...string) string {
	loginAllowed := "{{ true }}"
	if passwordResume {
		loginAllowed = "{{ false }}"
		if len(groupSID) == 1 && groupSID[0] != "" {
			loginAllowed = fmt.Sprintf(`{{ $allowed := false }}{{ range .authorization.user.gids }}{{ if eq . %q }}{{ $allowed = true }}{{ end }}{{ end }}{{ $allowed }}`, groupSID[0])
		}
	}
	return fmt.Sprintf(`startMessage: '{{""}}'
ssh:
  addresses: ["0.0.0.0:2222"]
  keys:
    hostKeys: [%q]
    rememberMeNotification: '{{""}}'
  banner: '{{""}}'
  idleTimeout: 30s
  maxTimeout: 2m
  gracefulShutdownTimeout: 3s
session:
  type: fs
  storage: %q
  maxConnections: 4
  idleTimeout: 2m
  maxTimeout: 5m
auditlog:
  - name: default
    enabled: true
    identityFile: %q
    directory: %q
    minimumFreeBytes: 1048576
    recording:
      enabled: true
      directory: %q
      maximumSpoolBytes: 16777216
      retainFor: 1h
      targets: false
http:
  enabled: true
  addresses: ["0.0.0.0:8443"]
  domains: [app.example.org]
  tls:
    certificates:
      - certificateFile: %q
        privateKeyFile: %q
flows:
  - name: %s
    discoverAsSlug: Work
    auditlog: default
    authorization:
      type: local
      authorizedKeys: [%q]
      password:
        allowed: %t
        interactiveAllowed: %t
    environment:
      type: local
      name: %q
      uid: %q
      createIfAbsent: false
      updateIfDifferent: false
      deleteOnDispose: false
      killProcessesOnDispose: false
      deleteHomeTogetherWithUser: false
      portForwardingAllowed: false
      loginAllowed: %q
      shellCommand: ['C:\Windows\System32\cmd.exe', /D, /Q]
      execCommandPrefix: ['C:\Windows\System32\cmd.exe', /D, /Q, /C]
      banner: '{{""}}'
`, filepath.Join(root, "host-key"), filepath.Join(root, "sessions"), filepath.Join(root, "audit-key"), filepath.Join(root, "auditlog"), filepath.Join(root, "recordings"), filepath.Join(root, "tls-cert"), filepath.Join(root, "tls-key"), browserfixture.Flow, filepath.Join(root, "authorized-key"), passwordResume, passwordResume, user, sid, loginAllowed)
}

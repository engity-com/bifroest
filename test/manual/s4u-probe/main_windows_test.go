//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestContainerAccountCreationRejectsHost(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	if sid == "S-1-5-93-2-1" {
		t.Skip("requires an ordinary Windows host identity")
	}
	t.Setenv("BIFROEST_TEST_LOCAL_SAM_IN_CONTAINER", "1")
	_, err = prepareContainerTestUser()
	if err == nil || !strings.Contains(err.Error(), "requires ContainerAdministrator") {
		t.Fatalf("expected host account creation to be rejected, got %v", err)
	}
}

package sys

import (
	"testing"
)

func TestGetProcSelfAddress(t *testing.T) {
	actual := GetProcSelfAddress()
	if actual == 0 {
		t.Fatalf("self address should be non-zero; but got %v", actual)
	}
}

func TestGetPathnameOfSelf(t *testing.T) {
	actual, actualErr := GetPathnameOfSelf()
	if actualErr != nil {
		t.Fatalf("expected no error; but got: %v", actualErr)
	}

	if actual == "" {
		t.Errorf("expected non-empty result; but got: %q", actual)
	}
}

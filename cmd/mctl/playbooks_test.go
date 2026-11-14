package main

import (
	"strings"
	"testing"
)

func TestPlaybooksList(t *testing.T) {
	startCore(t)
	out, err := mctl(t, "", "playbooks", "--platform", "ios-xe")
	if err != nil || !strings.Contains(out, "ios-xe/tac-baseline  ") || !strings.Contains(out, " comandos  [base]\n") {
		t.Fatalf("ios-xe = %q %v", out, err)
	}
	if out, err = mctl(t, "", "playbooks", "--platform", "nada"); err != nil || out != "" {
		t.Fatalf("nada = %q %v", out, err)
	}
}

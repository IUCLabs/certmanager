//go:build linux

package main

import (
	"os"
	"syscall"
	"testing"
)

// The help-and-exit-zero branch is the whole point of the gate, and no CI
// container has a controlling terminal to reach it through /dev/tty. A pty
// allocated from /dev/ptmx is a real terminal, so the true branch is pinned
// here instead of skipped.
func TestIsTerminalDetectsAPTY(t *testing.T) {
	pty, err := os.OpenFile("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { _ = pty.Close() })

	if !isTerminal(pty) {
		t.Error("a pty is a terminal")
	}
}

//go:build integration && linux

package integration

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Under generate() the exit code is the only failure signal and every byte of
// stdout is fed to parsejson(). A bare invocation may therefore print help and
// exit zero on a terminal and nowhere else. /dev/null and a closed fd 1 are the
// traps: both leave the process holding a character device, so a stat of the
// file mode calls them terminals.
func TestBareInvocationHelpsOnlyATerminal(t *testing.T) {
	dir := t.TempDir()
	bin := buildBinary(t, dir, filepath.Join(dir, "absent.yaml"))

	t.Run("pipe", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		defer func() { _ = r.Close() }()

		code := runBare(t, bin, w)
		_ = w.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		assertMachineCaller(t, code, out)
	})

	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "stdout")
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		defer func() { _ = f.Close() }()

		code := runBare(t, bin, f)
		out, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		assertMachineCaller(t, code, out)
	})

	t.Run("unix socket", func(t *testing.T) {
		sock, peer := socketPair(t)
		code := runBare(t, bin, sock)
		// The child's copy went with it; dropping ours ends the peer's read.
		_ = sock.Close()
		out, err := io.ReadAll(peer)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		assertMachineCaller(t, code, out)
	})

	// Nothing written to /dev/null is observable, so the exit code carries the
	// whole contract here -- which is exactly the situation under generate().
	t.Run("dev null", func(t *testing.T) {
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatalf("open %s: %v", os.DevNull, err)
		}
		defer func() { _ = devNull.Close() }()

		if code := runBare(t, bin, devNull); code == 0 {
			t.Errorf("exit code = 0, want non-zero")
		}
	})

	// A nil file closes fd 1 across the exec. The Go runtime reopens it onto
	// /dev/null before main() runs, so the process sees a character device it
	// never chose.
	t.Run("closed fd 1", func(t *testing.T) {
		if code := runBare(t, bin, nil); code == 0 {
			t.Errorf("exit code = 0, want non-zero")
		}
	})

	t.Run("pty", func(t *testing.T) {
		master, slave := openPTY(t)
		drained := make(chan []byte, 1)
		go func() {
			out, _ := io.ReadAll(master)
			drained <- out
		}()

		code := runBare(t, bin, slave)
		// The child's copy is gone; dropping ours makes the master read EIO.
		_ = slave.Close()
		out := <-drained

		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
		if !strings.Contains(string(out), "Usage:") {
			t.Errorf("stdout = %q, want the help text", out)
		}
	})
}

func assertMachineCaller(t *testing.T, code int, stdout []byte) {
	t.Helper()
	if code == 0 {
		t.Errorf("exit code = 0, want non-zero (stdout %q)", stdout)
	}
	if len(stdout) != 0 {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

// runBare runs the binary with no arguments and stdout as fd 1. A nil stdout
// leaves fd 1 closed at exec.
func runBare(t *testing.T, bin string, stdout *os.File) int {
	t.Helper()
	proc, err := os.StartProcess(bin, []string{bin}, &os.ProcAttr{
		Env:   hermeticEnv(t),
		Files: []*os.File{nil, stdout, nil},
	})
	if err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	state, err := proc.Wait()
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	return state.ExitCode()
}

// socketPair returns a connected unix socket to hand the child as stdout, and
// the peer end to read back whatever reached it.
func socketPair(t *testing.T) (sock, peer *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	sock = os.NewFile(uintptr(fds[0]), "stdout-socket")
	peer = os.NewFile(uintptr(fds[1]), "stdout-socket-peer")
	t.Cleanup(func() { _ = sock.Close(); _ = peer.Close() })
	return sock, peer
}

// openPTY allocates a pty pair. CI containers have no controlling terminal, so
// this is the only way to exercise the branch that prints help and exits zero.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", syscall.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatalf("unlock pty: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatalf("pty number: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), syscall.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("open pty slave: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return m, s
}

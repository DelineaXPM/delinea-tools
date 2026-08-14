//go:build !windows

package secretscmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// writeExisting opens with O_NOFOLLOW, so a symlink at the path is refused
// rather than followed to its target. (writeSecretFile refuses symlinks at the
// Lstat; this covers the open-time guard that closes the race directly.)
func TestWriteExistingRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	li, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeExisting(link, []byte("s3cr3t"), li); err == nil {
		t.Errorf("got nil, want O_NOFOLLOW to refuse the symlink")
	}
	if b, _ := os.ReadFile(target); len(b) != 0 {
		t.Errorf("secret written through the symlink: %q", b)
	}
}

// A failure before the rename that installs the replacement must leave an
// existing target untouched: nothing may be destroyed on a failed write.
func TestWriteSecretFileKeepsOldContentsOnFailure(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "creds")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if err := writeSecretFile(target, []byte("new")); err == nil {
		t.Skip("directory still writable (running as root?)")
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "old" {
		t.Errorf("previous contents destroyed by a failed write: %q, %v", b, err)
	}
}

// writeSecretFile writes to a pre-existing FIFO the caller set up, taking the
// non-regular passthrough branch (writeExisting). A reader drains it so the
// write does not block.
func TestWriteSecretFileToFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pipe")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	got := make(chan string, 1)
	go func() {
		b, _ := os.ReadFile(p) // blocks until the writer opens and closes
		got <- string(b)
	}()
	if err := writeSecretFile(p, []byte("s3cr3t")); err != nil {
		t.Fatalf("writeSecretFile to FIFO: %v", err)
	}
	select {
	case v := <-got:
		if v != "s3cr3t" {
			t.Errorf("reader got %q, want s3cr3t", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader never received the payload")
	}
}

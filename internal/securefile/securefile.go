// Package securefile provides atomic writes for local credential material.
package securefile

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnsurePrivateDir creates path when needed, rejects symlinks/non-directories,
// and enforces the requested mode on an existing directory.
func EnsurePrivateDir(path string, perm os.FileMode) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, perm); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("credential directory is not a real directory: %s", path)
	}
	return os.Chmod(path, perm)
}

// WriteAtomic replaces a regular file without exposing a partially written
// credential. Non-regular existing destinations are rejected.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	if err := ensureRegular(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	fail := func(err error) error {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func ensureRegular(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to overwrite non-regular credential file: %s", path)
	}
	return nil
}

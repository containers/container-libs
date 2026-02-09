package fileutils

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// ReflinkOrCopy attempts to reflink the source to the destination fd.
// If reflinking fails, it tries copy_file_range for kernel-level copying.
// If that also fails, it falls back to io.Copy().
func ReflinkOrCopy(src, dst *os.File) error {
	err := unix.IoctlFileClone(int(dst.Fd()), int(src.Fd()))
	if err == nil {
		return nil
	}

	// Get source file size for copy_file_range
	srcInfo, statErr := src.Stat()
	if statErr != nil {
		// Fall back to io.Copy if we can't stat
		_, err = io.Copy(dst, src)
		return err
	}

	// Try copy_file_range - kernel-level copy, more efficient than userspace
	// but only works within the same filesystem
	if err := doCopyFileRange(src, dst, srcInfo.Size()); err == nil {
		return nil
	}

	// copy_file_range may have partially written data before failing,
	// so reset both file offsets and truncate dst before falling back.
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := dst.Truncate(0); err != nil {
		return err
	}

	// Fall back to userspace io.Copy
	_, err = io.Copy(dst, src)
	return err
}

// doCopyFileRange uses the copy_file_range syscall for kernel-level copying.
func doCopyFileRange(src, dst *os.File, size int64) error {
	remaining := size
	for remaining > 0 {
		n, err := unix.CopyFileRange(int(src.Fd()), nil, int(dst.Fd()), nil, int(remaining), 0)
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
		remaining -= int64(n)
	}
	return nil
}

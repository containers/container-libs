//go:build netbsd || freebsd || darwin

package archive

import (
	"archive/tar"
	"os"

	"golang.org/x/sys/unix"
)

func handleLChmod(_ *tar.Header, path string, mode os.FileMode) error {
	return unix.Fchmodat(unix.AT_FDCWD, path, uint32(mode), unix.AT_SYMLINK_NOFOLLOW)
}

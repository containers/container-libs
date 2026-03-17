//go:build !linux

package archive

import (
	"os"

	"go.podman.io/storage/pkg/idtools"
)

func GetWhiteoutConverter(_ WhiteoutFormat, _ any) TarWhiteoutConverter {
	return nil
}

func GetFileOwner(path string) (uint32, uint32, uint32, error) {
	return 0, 0, 0, nil
}

func mkdirAllWithDirmetaDelegate(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func mkdirAllAndChownWithDirmetaDelegate(path string, mode os.FileMode, ids idtools.IDPair) error {
	return idtools.MkdirAllAndChownNew(path, mode, ids)
}

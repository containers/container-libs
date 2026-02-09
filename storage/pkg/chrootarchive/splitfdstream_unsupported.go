//go:build windows || darwin

package chrootarchive

import (
	"fmt"
	"io"
	"os"
	"runtime"

	"go.podman.io/storage/pkg/archive"
)

// UnpackSplitFDStream is not supported on this platform.
func UnpackSplitFDStream(stream io.Reader, fds []*os.File, dest string, options *archive.TarOptions) error {
	return fmt.Errorf("UnpackSplitFDStream is not supported on %s", runtime.GOOS)
}

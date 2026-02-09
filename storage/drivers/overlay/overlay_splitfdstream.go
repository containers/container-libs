//go:build linux

package overlay

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"go.podman.io/storage/pkg/archive"
	"go.podman.io/storage/pkg/fileutils"
	"go.podman.io/storage/pkg/idtools"
	"go.podman.io/storage/pkg/splitfdstream"
	"golang.org/x/sys/unix"
)

// GetSplitFDStream generates a split FD stream from the layer differences.
// The returned ReadCloser contains the splitfdstream-formatted data, and the
// []*os.File slice contains the external file descriptors referenced by the stream.
// Regular files are passed as external file descriptors for reflink-based copying.
// The caller is responsible for closing both the ReadCloser and all file descriptors.
func (d *Driver) GetSplitFDStream(id, parent string, options *splitfdstream.GetSplitFDStreamOpts) (io.ReadCloser, []*os.File, error) {
	if options == nil {
		return nil, nil, fmt.Errorf("options cannot be nil")
	}

	dir := d.dir(id)
	if err := fileutils.Exists(dir); err != nil {
		return nil, nil, fmt.Errorf("layer %s does not exist: %w", id, err)
	}

	// Check if this is a composefs layer and mount the EROFS blob if so.
	// The mount FD is used to resolve file paths to their flat storage paths
	// via the trusted.overlay.redirect xattr.
	composefsData := d.getComposefsData(id)
	composefsMountFd := -1
	if err := fileutils.Exists(composefsData); err == nil {
		fd, err := openComposefsMount(composefsData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to mount composefs for layer %s: %w", id, err)
		}
		composefsMountFd = fd
		defer unix.Close(composefsMountFd)
	} else if !errors.Is(err, unix.ENOENT) {
		return nil, nil, err
	}

	logrus.Debugf("overlay: GetSplitFDStream for layer %s with parent %s", id, parent)

	// Set up ID mappings
	idMappings := options.IDMappings
	if idMappings == nil {
		idMappings = &idtools.IDMappings{}
	}

	// Get the diff path for file access (used for FD references)
	diffPath, err := d.getDiffPath(id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get diff path for layer %s: %w", id, err)
	}

	// Diff() handles naiveDiff and all the edge cases correctly.
	tarStream, err := d.Diff(id, idMappings, parent, nil, options.MountLabel)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate diff for layer %s: %w", id, err)
	}
	defer tarStream.Close()

	// Write splitfdstream data directly to a memfd to avoid buffering in memory.
	streamFd, err := unix.MemfdCreate("splitfdstream", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, nil, fmt.Errorf("memfd_create: %w", err)
	}
	streamFile := os.NewFile(uintptr(streamFd), "splitfdstream")

	var fds []*os.File
	writer := splitfdstream.NewWriter(streamFile)

	// Convert tar stream to splitfdstream
	err = convertTarToSplitFDStream(tarStream, writer, diffPath, composefsMountFd, &fds)
	if err != nil {
		streamFile.Close()
		for _, f := range fds {
			f.Close()
		}
		return nil, nil, fmt.Errorf("failed to convert tar to splitfdstream: %w", err)
	}

	if _, err := streamFile.Seek(0, io.SeekStart); err != nil {
		streamFile.Close()
		for _, f := range fds {
			f.Close()
		}
		return nil, nil, fmt.Errorf("failed to seek stream: %w", err)
	}

	logrus.Debugf("overlay: GetSplitFDStream complete for layer %s: numFDs=%d", id, len(fds))
	return streamFile, fds, nil
}

// convertTarToSplitFDStream converts a tar stream to a splitfdstream by parsing
// tar headers and replacing file content with file descriptor references.
func convertTarToSplitFDStream(tarStream io.ReadCloser, writer *splitfdstream.SplitFDStreamWriter, diffPath string, composefsMountFd int, fds *[]*os.File) error {
	tr := tar.NewReader(tarStream)

	// Open diff directory for safe file access
	diffDirFd, err := unix.Open(diffPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to open diff directory %s: %w", diffPath, err)
	}
	defer unix.Close(diffDirFd)

	// Reusable buffer for inline content, lazily allocated
	var buf []byte

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Write the tar header as inline data
		var headerBuf bytes.Buffer
		tw := tar.NewWriter(&headerBuf)
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to serialize tar header for %s: %w", header.Name, err)
		}
		if err := writer.WriteInline(headerBuf.Bytes()); err != nil {
			return fmt.Errorf("failed to write tar header for %s: %w", header.Name, err)
		}

		// Handle file content
		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			// Try to open file and write FD reference
			ok, err := tryWriteFileAsFDReference(writer, diffDirFd, composefsMountFd, header, fds)
			if err != nil {
				return fmt.Errorf("failed to write FD reference for %s: %w", header.Name, err)
			}
			if ok {
				// Skip the content in the tar stream since we're using FD reference
				if _, err := io.CopyN(io.Discard, tr, header.Size); err != nil {
					return fmt.Errorf("failed to skip content for %s: %w", header.Name, err)
				}
			} else {
				if buf == nil {
					buf = make([]byte, archive.CopyBufferSize)
				}
				// File not found in diff directory (e.g., naiveDiff was used),
				// write content inline from the tar stream.
				// Write a single prefix for the total size, then stream
				// data in chunks.  The reader expects exactly one prefix
				// per file entry.
				if err := writer.WriteInlinePrefix(header.Size); err != nil {
					return fmt.Errorf("failed to write inline prefix for %s: %w", header.Name, err)
				}
				remaining := header.Size
				for remaining > 0 {
					toRead := int64(len(buf))
					if toRead > remaining {
						toRead = remaining
					}
					n, err := io.ReadFull(tr, buf[:toRead])
					if err != nil {
						return fmt.Errorf("failed to read content for %s: %w", header.Name, err)
					}
					if err := writer.WriteRaw(buf[:n]); err != nil {
						return fmt.Errorf("failed to write inline content for %s: %w", header.Name, err)
					}
					remaining -= int64(n)
				}
			}
		}
	}

	return nil
}

// tryWriteFileAsFDReference tries to open a file and write an FD reference to the splitfdstream.
// Returns (true, nil) if the file was successfully written as FD reference.
// Returns (false, nil) if the file doesn't exist in the diff directory (caller should write inline).
// Returns (_, error) on other errors.
//
// When composefsMountFd >= 0, the diff directory uses a flat layout (files stored by digest).
// The file path is resolved by reading the trusted.overlay.redirect xattr from the composefs mount.
func tryWriteFileAsFDReference(writer *splitfdstream.SplitFDStreamWriter, diffDirFd int, composefsMountFd int, header *tar.Header, fds *[]*os.File) (bool, error) {
	// Clean the file name to prevent path traversal
	cleanName := filepath.Clean(header.Name)
	if strings.Contains(cleanName, "..") {
		return false, fmt.Errorf("invalid file path: %s", header.Name)
	}

	var fd int
	var openErr error

	if composefsMountFd >= 0 {
		// Composefs: open the file in the composefs mount to read the redirect xattr,
		// which gives the flat storage path in the diff directory.
		cfd, err := unix.Openat2(composefsMountFd, cleanName, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_PATH,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
		})
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
				return false, nil
			}
			return false, fmt.Errorf("failed to open %s in composefs mount: %w", cleanName, err)
		}
		buf := make([]byte, unix.PathMax)
		n, err := unix.Fgetxattr(cfd, "trusted.overlay.redirect", buf)
		unix.Close(cfd)
		if err != nil {
			if errors.Is(err, unix.ENODATA) {
				return false, nil
			}
			return false, fmt.Errorf("failed to get redirect xattr for %s: %w", cleanName, err)
		}

		flatPath := string(buf[:n])
		if strings.Contains(flatPath, "..") || filepath.IsAbs(flatPath) {
			return false, fmt.Errorf("invalid redirect xattr value for %s: %s", cleanName, flatPath)
		}

		fd, openErr = unix.Openat2(diffDirFd, flatPath, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
		})
	} else {
		// Non-composefs: open directly by name under the diff directory
		fd, openErr = unix.Openat2(diffDirFd, cleanName, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
		})
	}

	if openErr != nil {
		if errors.Is(openErr, unix.ENOENT) || errors.Is(openErr, unix.ELOOP) {
			return false, nil
		}
		return false, fmt.Errorf("failed to open %s: %w", cleanName, openErr)
	}

	// Verify it's still a regular file
	var fdStat unix.Stat_t
	if err := unix.Fstat(fd, &fdStat); err != nil {
		unix.Close(fd)
		return false, fmt.Errorf("failed to fstat opened file %s: %w", cleanName, err)
	}
	if fdStat.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return false, fmt.Errorf("file %s is not a regular file", cleanName)
	}

	// Create os.File from fd
	f := os.NewFile(uintptr(fd), cleanName)
	if f == nil {
		unix.Close(fd)
		return false, fmt.Errorf("failed to create File from fd for %s", cleanName)
	}

	fdIndex := len(*fds)

	// Write FD reference before appending to the slice so that on
	// error the caller's cleanup loop does not see a stale entry.
	if err := writer.WriteExternal(fdIndex); err != nil {
		f.Close()
		return false, fmt.Errorf("failed to write external FD reference: %w", err)
	}

	*fds = append(*fds, f)

	return true, nil
}

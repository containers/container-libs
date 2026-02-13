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
	"go.podman.io/storage/pkg/chrootarchive"
	"go.podman.io/storage/pkg/directory"
	"go.podman.io/storage/pkg/fileutils"
	"go.podman.io/storage/pkg/idtools"
	"go.podman.io/storage/pkg/splitfdstream"
	"go.podman.io/storage/pkg/unshare"
	"golang.org/x/sys/unix"
)

// ErrSplitFDStreamNotSupported is returned when splitfdstream operations
// are not supported for a layer (e.g., composefs layers).
var ErrSplitFDStreamNotSupported = errors.New("splitfdstream not supported for this layer")

// untarSplitFDStream defines the splitfdstream untar method (through chrootarchive for security isolation)
var untarSplitFDStream = chrootarchive.UnpackSplitFDStream

// ApplySplitFDStream applies changes from a split FD stream to the specified layer.
// It iterates over the splitfdstream entries and extracts them using
// archive.UnpackFromIterator, which enables reflink-based copying for
// external file descriptor references.
// This API is experimental and can be changed without bumping the major version number.
func (d *Driver) ApplySplitFDStream(options *splitfdstream.ApplySplitFDStreamOpts) (int64, error) {
	if options == nil {
		return 0, fmt.Errorf("options cannot be nil")
	}
	if err := options.Validate(); err != nil {
		return 0, fmt.Errorf("invalid options: %w", err)
	}

	var diffPath string

	if options.StagingDir != "" {
		diffPath = options.StagingDir
		logrus.Debugf("overlay: ApplySplitFDStream applying to staging dir %s", diffPath)
	} else {
		dir := d.dir(options.LayerID)
		if err := fileutils.Exists(dir); err != nil {
			return 0, fmt.Errorf("layer %s does not exist: %w", options.LayerID, err)
		}

		composefsData := d.getComposefsData(options.LayerID)
		if err := fileutils.Exists(composefsData); err == nil {
			return 0, fmt.Errorf("%w: layer %s uses composefs", ErrSplitFDStreamNotSupported, options.LayerID)
		}

		var err error
		diffPath, err = d.getDiffPath(options.LayerID)
		if err != nil {
			return 0, fmt.Errorf("failed to get diff path for layer %s: %w", options.LayerID, err)
		}

		logrus.Debugf("overlay: ApplySplitFDStream applying to layer %s at %s", options.LayerID, diffPath)
	}

	idMappings := options.IDMappings
	if idMappings == nil {
		idMappings = &idtools.IDMappings{}
	}

	if err := untarSplitFDStream(options.Stream, options.FileDescriptors, diffPath, &archive.TarOptions{
		UIDMaps:           idMappings.UIDs(),
		GIDMaps:           idMappings.GIDs(),
		IgnoreChownErrors: options.IgnoreChownErrors || d.options.ignoreChownErrors,
		WhiteoutFormat:    d.getWhiteoutFormat(),
		ForceMask:         options.ForceMask,
		InUserNS:          unshare.IsRootless(),
	}); err != nil {
		return 0, fmt.Errorf("failed to apply split FD stream: %w", err)
	}

	return directory.Size(diffPath)
}

// GetSplitFDStream generates a split FD stream from the layer differences.
// The returned ReadCloser contains the splitfdstream-formatted data, and the
// []*os.File slice contains the external file descriptors referenced by the stream.
// Regular files are passed as external file descriptors for reflink-based copying.
// The caller is responsible for closing both the ReadCloser and all file descriptors.
// This API is experimental and can be changed without bumping the major version number.
func (d *Driver) GetSplitFDStream(id, parent string, options *splitfdstream.GetSplitFDStreamOpts) (io.ReadCloser, []*os.File, error) {
	if options == nil {
		return nil, nil, fmt.Errorf("options cannot be nil")
	}

	dir := d.dir(id)
	if err := fileutils.Exists(dir); err != nil {
		return nil, nil, fmt.Errorf("layer %s does not exist: %w", id, err)
	}

	// Check if this is a composefs layer - splitfdstream is not supported for composefs yet
	composefsData := d.getComposefsData(id)
	if err := fileutils.Exists(composefsData); err == nil {
		return nil, nil, fmt.Errorf("%w: layer %s uses composefs", ErrSplitFDStreamNotSupported, id)
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

	// Use Diff() to generate the tar stream - it handles naiveDiff
	// and all the edge cases correctly.
	tarStream, err := d.Diff(id, idMappings, parent, nil, options.MountLabel)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate diff for layer %s: %w", id, err)
	}
	defer tarStream.Close()

	// Buffer the splitfdstream data in memory
	var buf bytes.Buffer
	var fds []*os.File
	writer := splitfdstream.NewWriter(&buf)

	// Convert tar stream to splitfdstream
	err = d.convertTarToSplitFDStream(tarStream, writer, diffPath, &fds)
	if err != nil {
		// Close any opened FDs on error
		for _, f := range fds {
			f.Close()
		}
		return nil, nil, fmt.Errorf("failed to convert tar to splitfdstream: %w", err)
	}

	logrus.Debugf("overlay: GetSplitFDStream complete for layer %s: streamSize=%d, numFDs=%d", id, buf.Len(), len(fds))
	return io.NopCloser(bytes.NewReader(buf.Bytes())), fds, nil
}

// convertTarToSplitFDStream converts a tar stream to a splitfdstream by parsing
// tar headers and replacing file content with file descriptor references.
func (d *Driver) convertTarToSplitFDStream(tarStream io.ReadCloser, writer *splitfdstream.SplitFDStreamWriter, diffPath string, fds *[]*os.File) error {
	tr := tar.NewReader(tarStream)

	// Open diff directory for safe file access
	diffDirFd, err := unix.Open(diffPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to open diff directory %s: %w", diffPath, err)
	}
	defer unix.Close(diffDirFd)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Write the tar header as inline data
		if err := d.writeTarHeaderInline(writer, header); err != nil {
			return fmt.Errorf("failed to write tar header for %s: %w", header.Name, err)
		}

		// Handle file content
		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			// Try to open file and write FD reference
			ok, err := d.tryWriteFileAsFDReference(writer, diffDirFd, header, fds)
			if err != nil {
				return fmt.Errorf("failed to write FD reference for %s: %w", header.Name, err)
			}
			if ok {
				// Skip the content in the tar stream since we're using FD reference
				if _, err := io.CopyN(io.Discard, tr, header.Size); err != nil {
					return fmt.Errorf("failed to skip content for %s: %w", header.Name, err)
				}
			} else {
				// File not found in diff directory (e.g., naiveDiff was used),
				// write content inline from the tar stream
				content := make([]byte, header.Size)
				if _, err := io.ReadFull(tr, content); err != nil {
					return fmt.Errorf("failed to read content for %s: %w", header.Name, err)
				}
				if err := writer.WriteInline(content); err != nil {
					return fmt.Errorf("failed to write inline content for %s: %w", header.Name, err)
				}
			}
		}
		// For non-regular files or empty files, there's no content to handle
	}

	return nil
}

// writeTarHeaderInline writes a tar header as inline data to the splitfdstream.
func (d *Driver) writeTarHeaderInline(writer *splitfdstream.SplitFDStreamWriter, header *tar.Header) error {
	var headerBuf bytes.Buffer
	tw := tar.NewWriter(&headerBuf)
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to serialize tar header: %w", err)
	}

	headerBytes := headerBuf.Bytes()
	if len(headerBytes) > 0 {
		if err := writer.WriteInline(headerBytes); err != nil {
			return fmt.Errorf("failed to write inline header: %w", err)
		}
	}

	return nil
}

// tryWriteFileAsFDReference tries to open a file and write an FD reference to the splitfdstream.
// Returns (true, nil) if the file was successfully written as FD reference.
// Returns (false, nil) if the file doesn't exist in the diff directory (caller should write inline).
// Returns (false, error) on other errors.
func (d *Driver) tryWriteFileAsFDReference(writer *splitfdstream.SplitFDStreamWriter, diffDirFd int, header *tar.Header, fds *[]*os.File) (bool, error) {
	// Clean the file name to prevent path traversal
	cleanName := filepath.Clean(header.Name)
	if strings.Contains(cleanName, "..") {
		return false, fmt.Errorf("invalid file path: %s", header.Name)
	}

	// Open the file safely using openat2
	fd, err := unix.Openat2(diffDirFd, cleanName, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_BENEATH,
	})
	if err != nil {
		// File not found in diff directory - caller should write inline
		return false, nil
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
	*fds = append(*fds, f)

	// Write FD reference
	if err := writer.WriteExternal(fdIndex); err != nil {
		return false, fmt.Errorf("failed to write external FD reference: %w", err)
	}

	return true, nil
}

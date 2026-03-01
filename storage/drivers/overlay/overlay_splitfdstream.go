//go:build linux

package overlay

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
	"go.podman.io/storage/pkg/archive"
	"go.podman.io/storage/pkg/chrootarchive"
	"go.podman.io/storage/pkg/directory"
	"go.podman.io/storage/pkg/fileutils"
	"go.podman.io/storage/pkg/fsverity"
	"go.podman.io/storage/pkg/idtools"
	"go.podman.io/storage/pkg/splitfdstream"
	"go.podman.io/storage/pkg/unshare"
	"golang.org/x/sys/unix"
)

// untarSplitFDStream defines the splitfdstream untar method (through chrootarchive for security isolation)
var untarSplitFDStream = chrootarchive.UnpackSplitFDStream

// ApplySplitFDStream applies changes from a split FD stream to the specified layer.
// It iterates over the splitfdstream entries and extracts them using
// archive.UnpackFromIterator, which enables reflink-based copying for
// external file descriptor references.
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

		var err error
		diffPath, err = d.getDiffPath(options.LayerID)
		if err != nil {
			return 0, fmt.Errorf("failed to get diff path for layer %s: %w", options.LayerID, err)
		}

		logrus.Debugf("overlay: ApplySplitFDStream applying to layer %s at %s", options.LayerID, diffPath)
	}

	// For composefs layers, process the splitfdstream iterator directly:
	// build the TOC from tar headers and write regular files to flat
	// content-addressable paths, preserving reflinks from FD references.
	if d.usingComposefs && options.LayerID != "" {
		iter := archive.NewSplitFDStreamIterator(options.Stream, options.FileDescriptors)
		headers, contentDigests, verityDigests, err := extractToFlatLayout(iter, diffPath)
		if err != nil {
			return 0, fmt.Errorf("failed to extract to flat layout: %w", err)
		}
		if err := generateComposeFsBlobFromHeaders(headers, contentDigests, verityDigests, d.getComposefsData(options.LayerID)); err != nil {
			return 0, fmt.Errorf("failed to generate composefs blob: %w", err)
		}
		return directory.Size(diffPath)
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
	err = convertTarToSplitFDStream(tarStream, writer, diffPath, composefsMountFd, &fds)
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
					buf = make([]byte, 1<<20)
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
	*fds = append(*fds, f)

	// Write FD reference
	if err := writer.WriteExternal(fdIndex); err != nil {
		return false, fmt.Errorf("failed to write external FD reference: %w", err)
	}

	return true, nil
}

// extractToFlatLayout iterates a TarEntryIterator and writes regular file
// content to flat content-addressable paths under flatDir (preserving reflinks
// from FD references via WriteContentTo).  It returns the collected tar headers,
// content digests, and verity digests for composefs blob generation.
func extractToFlatLayout(iter archive.TarEntryIterator, flatDir string) ([]*tar.Header, map[string]string, map[string]string, error) {
	var headers []*tar.Header
	contentDigests := make(map[string]string)
	verityDigests := make(map[string]string)
	createdDirs := make(map[string]struct{})

	for {
		hdr, err := iter.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, err
		}

		headers = append(headers, hdr)

		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			dgst, flatPath, verity, err := writeContentToFlatPath(flatDir, func(dst *os.File) error {
				return iter.WriteContentTo(dst)
			}, createdDirs)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to write content for %s: %w", hdr.Name, err)
			}
			contentDigests[hdr.Name] = dgst.String()
			if verity != "" {
				verityDigests[flatPath] = verity
			}
		}
	}

	return headers, contentDigests, verityDigests, nil
}

// writeContentToFlatPath creates a temporary file, writes content via callback while
// computing digest, and atomically places it at the content-addressable path.
// This follows the same pattern as destinationFile in the chunked package.
func writeContentToFlatPath(flatDir string, writeContent func(dst *os.File) error, createdDirs map[string]struct{}) (digest.Digest, string, string, error) {
	flatFile, err := openFlatContentFile(flatDir)
	if err != nil {
		return "", "", "", err
	}
	defer func() {
		if flatFile.file != nil {
			flatFile.file.Close()
		}
	}()

	// Write content to file directly (for reflink support), then compute digest
	if err := writeContent(flatFile.file); err != nil {
		return "", "", "", err
	}

	// Now compute digest by reading back (following destinationFile validation pattern)
	if _, err := flatFile.file.Seek(0, io.SeekStart); err != nil {
		return "", "", "", err
	}
	if _, err := io.Copy(flatFile.hash, flatFile.file); err != nil {
		return "", "", "", err
	}

	// Get digest and place file atomically
	dgst := flatFile.digester.Digest()
	flatPath, err := regularFilePathForValidatedDigest(dgst)
	if err != nil {
		return "", "", "", err
	}

	// Create directory structure if needed
	flatSubDir := filepath.Dir(flatPath)
	if _, exists := createdDirs[flatSubDir]; !exists {
		if err := os.MkdirAll(filepath.Join(flatDir, flatSubDir), 0o755); err != nil {
			return "", "", "", err
		}
		createdDirs[flatSubDir] = struct{}{}
	}

	// Atomically link to final path
	destPath := filepath.Join(flatDir, flatPath)
	procPath := fmt.Sprintf("/proc/self/fd/%d", flatFile.file.Fd())
	if err := unix.Linkat(unix.AT_FDCWD, procPath, unix.AT_FDCWD, destPath, unix.AT_SYMLINK_FOLLOW); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return "", "", "", fmt.Errorf("failed to link to %s: %w", destPath, err)
		}
	}

	// Enable fs-verity if supported (same pattern as destinationFile)
	verity := enableFlatFileVerity(destPath, flatPath)

	return dgst, flatPath, verity, nil
}

// flatContentFile follows the same validation pattern as destinationFile but for content-addressable storage
type flatContentFile struct {
	file     *os.File
	digester digest.Digester
	hash     hash.Hash
}

// openFlatContentFile creates a flatContentFile using the same pattern as openDestinationFile
func openFlatContentFile(flatDir string) (*flatContentFile, error) {
	tmpFile, err := openLinkableTmpFile(flatDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	// Follow same pattern as destinationFile for validation
	digester := digest.Canonical.Digester()
	hash := digester.Hash()

	return &flatContentFile{
		file:     tmpFile,
		digester: digester,
		hash:     hash,
	}, nil
}

// enableFlatFileVerity enables fs-verity on a flat file and returns the verity digest
func enableFlatFileVerity(destPath, flatPath string) string {
	roFile, err := os.Open(destPath)
	if err != nil {
		return ""
	}
	defer roFile.Close()

	if err := fsverity.EnableVerity(flatPath, int(roFile.Fd())); err != nil {
		return ""
	}
	verity, err := fsverity.MeasureVerity(flatPath, int(roFile.Fd()))
	if err != nil {
		return ""
	}
	return verity
}

// openLinkableTmpFile creates a temporary file that can be linked to a final path
// via /proc/self/fd/N. Uses O_TMPFILE when supported, falls back to CreateTemp + unlink.
func openLinkableTmpFile(dir string) (*os.File, error) {
	file, err := os.OpenFile(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o644)
	if err == nil {
		return file, nil
	}
	// Fallback: create and immediately unlink
	file, err = os.CreateTemp(dir, ".flatfile-*")
	if err != nil {
		return nil, err
	}
	_ = os.Remove(file.Name())
	return file, nil
}

// regularFilePathForValidatedDigest returns the path used in the composefs backing store
func regularFilePathForValidatedDigest(d digest.Digest) (string, error) {
	if algo := d.Algorithm(); algo != digest.SHA256 {
		return "", fmt.Errorf("unexpected digest algorithm %q", algo)
	}
	e := d.Encoded()
	return e[0:2] + "/" + e[2:], nil
}

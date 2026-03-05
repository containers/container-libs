package archive

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"go.podman.io/storage/pkg/fileutils"
)

// splitFDStreamIterator implements TarEntryIterator for splitfdstream data.
// It parses the splitfdstream format and provides tar headers.
// For external FD references, WriteContentTo uses ReflinkOrCopy to efficiently
// copy file content via reflinks when possible.
type splitFDStreamIterator struct {
	stream    io.Reader
	fds       []*os.File
	contentFD *os.File  // FD for current entry's content (external reference)
	content   io.Reader // reader for current entry's inline content
}

// NewSplitFDStreamIterator creates a TarEntryIterator that reads entries from
// a splitfdstream-formatted stream, using the provided file descriptors for
// external content references.
func NewSplitFDStreamIterator(stream io.Reader, fds []*os.File) TarEntryIterator {
	return &splitFDStreamIterator{
		stream: stream,
		fds:    fds,
	}
}

func (i *splitFDStreamIterator) Next() (*tar.Header, error) {
	var prefix int64
	err := binary.Read(i.stream, binary.LittleEndian, &prefix)
	if err == io.EOF {
		return nil, io.EOF
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read chunk prefix: %w", err)
	}

	if prefix >= 0 {
		return nil, fmt.Errorf("expected inline chunk for tar header, got external reference %d", prefix)
	}

	// Inline chunk: read the serialized tar header
	dataLen := int(-prefix)
	headerData := make([]byte, dataLen)
	if _, err := io.ReadFull(i.stream, headerData); err != nil {
		return nil, fmt.Errorf("failed to read inline data: %w", err)
	}

	header, err := tar.NewReader(bytes.NewReader(headerData)).Next()
	if err != nil {
		return nil, fmt.Errorf("failed to parse tar header from inline chunk: %w", err)
	}

	// Reset content state
	i.contentFD = nil
	i.content = nil

	// For regular files with content, read the next chunk to determine source
	if header.Typeflag == tar.TypeReg && header.Size > 0 {
		if err := binary.Read(i.stream, binary.LittleEndian, &prefix); err != nil {
			return nil, fmt.Errorf("failed to read content chunk prefix for %q: %w", header.Name, err)
		}

		if prefix < 0 {
			// Inline content
			contentLen := -prefix
			i.content = io.LimitReader(i.stream, contentLen)
		} else {
			// External content from FD
			fdIndex := int(prefix)
			if fdIndex >= len(i.fds) {
				return nil, fmt.Errorf("fd index %d out of range (have %d fds)", fdIndex, len(i.fds))
			}
			i.contentFD = i.fds[fdIndex]
		}
	}

	return header, nil
}

func (i *splitFDStreamIterator) WriteContentTo(dst *os.File) error {
	if i.contentFD != nil {
		return fileutils.ReflinkOrCopy(i.contentFD, dst)
	}
	if i.content != nil {
		_, err := io.Copy(dst, i.content)
		return err
	}
	return nil
}

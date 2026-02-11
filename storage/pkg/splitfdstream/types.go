package splitfdstream

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"go.podman.io/storage/pkg/idtools"
)

// SplitFDStreamDriver defines the interface that storage drivers must implement
// to support splitfdstream operations.
type SplitFDStreamDriver interface {
	// ApplySplitFDStream applies a splitfdstream to a layer.
	ApplySplitFDStream(options *ApplySplitFDStreamOpts) (int64, error)

	// GetSplitFDStream generates a splitfdstream for a layer.
	GetSplitFDStream(id, parent string, options *GetSplitFDStreamOpts) (io.ReadCloser, []*os.File, error)
}

// ApplySplitFDStreamOpts provides options for ApplySplitFDStream operations.
type ApplySplitFDStreamOpts struct {
	LayerID           string
	Stream            io.Reader
	FileDescriptors   []*os.File
	IgnoreChownErrors bool
	MountLabel        string
	StagingDir        string
	IDMappings        *idtools.IDMappings
	ForceMask         *os.FileMode
}

// Validate checks if the options are valid.
func (opts *ApplySplitFDStreamOpts) Validate() error {
	if opts.LayerID == "" && opts.StagingDir == "" {
		return fmt.Errorf("either LayerID or StagingDir must be specified")
	}
	return nil
}

// GetSplitFDStreamOpts provides options for GetSplitFDStream operations.
type GetSplitFDStreamOpts struct {
	MountLabel string
	IDMappings *idtools.IDMappings
}

// SplitFDStreamWriter writes data in the composefs-rs splitfdstream format.
// The format uses signed 64-bit little-endian prefixes:
// - Negative prefix: abs(prefix) bytes of inline data follow
// - Non-negative prefix: reference to external file descriptor at index prefix
type SplitFDStreamWriter struct {
	writer io.Writer
}

// NewWriter creates a new SplitFDStreamWriter.
func NewWriter(w io.Writer) *SplitFDStreamWriter {
	return &SplitFDStreamWriter{writer: w}
}

// WriteInline writes inline data with a negative prefix indicating the data length.
func (w *SplitFDStreamWriter) WriteInline(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	prefix := int64(-len(data))
	if err := binary.Write(w.writer, binary.LittleEndian, prefix); err != nil {
		return fmt.Errorf("failed to write inline prefix: %w", err)
	}
	if _, err := w.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write inline data: %w", err)
	}
	return nil
}

// WriteExternal writes a reference to an external file descriptor.
func (w *SplitFDStreamWriter) WriteExternal(fdIndex int) error {
	prefix := int64(fdIndex)
	if err := binary.Write(w.writer, binary.LittleEndian, prefix); err != nil {
		return fmt.Errorf("failed to write external fd reference: %w", err)
	}
	return nil
}

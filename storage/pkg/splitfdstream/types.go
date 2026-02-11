package splitfdstream

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.podman.io/storage/pkg/idtools"
)

// Store represents the minimal interface needed for image metadata access.
type Store interface {
	ImageBigData(id, key string) ([]byte, error)
	ListImageBigData(id string) ([]string, error)
	ResolveImageID(id string) (actualID string, topLayerID string, err error)
	LayerParent(id string) (parentID string, err error)
}

// SplitFDStreamDriver defines the interface that storage drivers must implement
// to support splitfdstream operations.
type SplitFDStreamDriver interface {
	// ApplySplitFDStream applies a splitfdstream to a layer.
	ApplySplitFDStream(options *ApplySplitFDStreamOpts) (int64, error)

	// GetSplitFDStream generates a splitfdstream for a layer.
	GetSplitFDStream(id, parent string, options *GetSplitFDStreamOpts) (io.ReadCloser, []*os.File, error)
}

// ImageMetadata holds manifest and config data for an OCI image.
type ImageMetadata struct {
	ManifestJSON []byte   `json:"manifest"`
	ConfigJSON   []byte   `json:"config"`
	LayerDigests []string `json:"layerDigests"`
}

// findManifest finds the image manifest from BigData keys.
// It looks for manifest-* keys containing an image manifest (has "config" field),
// filtering out manifest lists/indexes.
func findManifest(store Store, imageID string) ([]byte, error) {
	availableKeys, err := store.ListImageBigData(imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to list BigData keys for %s: %w", imageID, err)
	}

	// Try manifest-* keys that contain an actual image manifest (not a manifest list).
	// An image manifest has a config descriptor; a manifest list/index does not.
	for _, key := range availableKeys {
		if !strings.HasPrefix(key, "manifest") {
			continue
		}
		data, err := store.ImageBigData(imageID, key)
		if err != nil {
			continue
		}
		var manifest v1.Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			continue
		}
		if manifest.Config.MediaType != "" {
			return data, nil
		}
	}

	// Fall back to generic "manifest" key
	data, err := store.ImageBigData(imageID, "manifest")
	if err != nil {
		return nil, fmt.Errorf("no manifest found for image %s", imageID)
	}
	return data, nil
}

// findConfig finds the image config from BigData keys.
// Config is typically stored under a digest-format key (e.g., "sha256:abc...").
func findConfig(store Store, imageID string) ([]byte, error) {
	availableKeys, err := store.ListImageBigData(imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to list BigData keys for %s: %w", imageID, err)
	}

	// Look for digest-format keys that aren't manifests
	for _, key := range availableKeys {
		if strings.Contains(key, ":") && !strings.HasPrefix(key, "manifest") {
			data, err := store.ImageBigData(imageID, key)
			if err == nil {
				return data, nil
			}
		}
	}

	return nil, fmt.Errorf("no config found for image %s", imageID)
}

// GetImageMetadata retrieves manifest, config, and layer information for an image.
func GetImageMetadata(store Store, imageID string) (*ImageMetadata, error) {
	actualID, topLayerID, err := store.ResolveImageID(imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve image %s: %w", imageID, err)
	}

	manifestJSON, err := findManifest(store, actualID)
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest for %s (resolved to %s): %w", imageID, actualID, err)
	}

	configJSON, err := findConfig(store, actualID)
	if err != nil {
		return nil, fmt.Errorf("failed to get config for %s (resolved to %s): %w", imageID, actualID, err)
	}

	// Walk the layer chain using store.LayerParent
	var layerIDs []string
	layerID := topLayerID
	for layerID != "" {
		layerIDs = append(layerIDs, layerID)
		parentID, err := store.LayerParent(layerID)
		if err != nil {
			break
		}
		layerID = parentID
	}

	// Fall back to manifest layer digests if layer chain traversal failed
	if len(layerIDs) == 0 {
		var manifest v1.Manifest
		if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
			return nil, fmt.Errorf("failed to parse manifest: %w", err)
		}
		layerIDs = make([]string, len(manifest.Layers))
		for i, layer := range manifest.Layers {
			layerIDs[i] = layer.Digest.String()
		}
	}

	return &ImageMetadata{
		ManifestJSON: manifestJSON,
		ConfigJSON:   configJSON,
		LayerDigests: layerIDs,
	}, nil
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

// WriteInlinePrefix writes a negative prefix indicating that size bytes of
// inline data will follow.  Use WriteRaw to write the actual data in chunks.
// This is useful when the data is too large to fit in a single WriteInline call.
func (w *SplitFDStreamWriter) WriteInlinePrefix(size int64) error {
	if size <= 0 {
		return nil
	}
	prefix := -size
	if err := binary.Write(w.writer, binary.LittleEndian, prefix); err != nil {
		return fmt.Errorf("failed to write inline prefix: %w", err)
	}
	return nil
}

// WriteRaw writes raw data without any prefix framing.
// Must be preceded by a WriteInlinePrefix call with the total size.
func (w *SplitFDStreamWriter) WriteRaw(data []byte) error {
	if _, err := w.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write raw data: %w", err)
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

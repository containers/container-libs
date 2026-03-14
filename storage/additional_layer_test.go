//go:build linux

package storage

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	digest "github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupAdditionalLayerStore creates a temporary additional layer store directory
// with the expected structure for the given tocDigest and image reference.
// The info file contains the provided content.
func setupAdditionalLayerStore(t *testing.T, tocDigest digest.Digest, imageRef string, infoContent string) string {
	t.Helper()
	alsRoot := t.TempDir()

	refDir := base64.StdEncoding.EncodeToString([]byte(imageRef))
	layerDir := filepath.Join(alsRoot, refDir, tocDigest.String())
	require.NoError(t, os.MkdirAll(layerDir, 0o755))

	require.NoError(t, os.MkdirAll(filepath.Join(layerDir, "diff"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(layerDir, "info"), []byte(infoContent), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(layerDir, "blob"), []byte{}, 0o644))

	return alsRoot
}

func TestLookupAdditionalLayerSuccess(t *testing.T) {
	prevLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.ErrorLevel)
	t.Cleanup(func() { logrus.SetLevel(prevLevel) })

	tocDigest := digest.FromString("test-layer")
	imageRef := "fedora"

	info := Layer{
		ID:             "test-id",
		CompressedSize: 42,
		TOCDigest:      tocDigest,
	}
	infoJSON, err := json.Marshal(info)
	require.NoError(t, err)

	alsPath := setupAdditionalLayerStore(t, tocDigest, imageRef, string(infoJSON))
	store := newTestStore(t, StoreOptions{
		GraphDriverName:    "overlay",
		GraphDriverOptions: []string{"additionallayerstore=" + alsPath + ":ref"},
	})
	t.Cleanup(func() { _, _ = store.Shutdown(true) })

	al, err := store.LookupAdditionalLayer(tocDigest, imageRef)
	require.NoError(t, err)
	defer al.Release()

	assert.Equal(t, tocDigest, al.TOCDigest())
	assert.Equal(t, int64(42), al.CompressedSize())
}

func TestLookupAdditionalLayerDecodeError(t *testing.T) {
	prevLevel := logrus.GetLevel()
	logrus.SetLevel(logrus.ErrorLevel)
	t.Cleanup(func() { logrus.SetLevel(prevLevel) })

	tocDigest := digest.FromString("test-layer")
	imageRef := "fedora"

	alsPath := setupAdditionalLayerStore(t, tocDigest, imageRef, "not valid json")
	store := newTestStore(t, StoreOptions{
		GraphDriverName:    "overlay",
		GraphDriverOptions: []string{"additionallayerstore=" + alsPath + ":ref"},
	})
	t.Cleanup(func() { _, _ = store.Shutdown(true) })

	_, err := store.LookupAdditionalLayer(tocDigest, imageRef)
	assert.Error(t, err, "should fail on invalid JSON in info file")
}

package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/types"
)

func TestNewArtifactReference(t *testing.T) {
	// Test valid reference
	ar, err := NewArtifactReference("quay.io/podman/machine-os:5.1")
	assert.NoError(t, err)
	assert.NotNil(t, ar.Named)
	assert.Equal(t, "quay.io/podman/machine-os:5.1", ar.Named.String())

	// Test another valid reference
	ar, err = NewArtifactReference("docker.io/library/nginx:latest")
	assert.NoError(t, err)
	assert.NotNil(t, ar.Named)

	// Test invalid reference - empty string
	_, err = NewArtifactReference("")
	assert.Error(t, err)

	// Test invalid reference - malformed
	_, err = NewArtifactReference("invalid::reference")
	assert.Error(t, err)

	// Test latest is added when no tag is provided
	ar, err = NewArtifactReference("quay.io/machine-os/podman")
	assert.NoError(t, err)
	assert.Equal(t, "quay.io/machine-os/podman:latest", ar.Named.String())

	// Input with a digest is good
	ar, err = NewArtifactReference("quay.io/machine-os/podman@sha256:8b96f36deaf1d2713858eebd9ef2fee9610df8452fbd083bbfa7dca66d6fcd0b")
	assert.NoError(t, err)
	assert.True(t, ar.IsDigested())

	// Partial digests are a no-go
	_, err = NewArtifactReference("quay.io/machine-os/podman@sha256:8b96f36deaf1d2")
	assert.Error(t, err)

	// "IDs" are also a no-go
	_, err = NewArtifactReference("84ddb405470e733d0202d6946e48fc75a7ee231337bdeb31a8579407a7052d9e")
	assert.Error(t, err)
}

func TestArtifactReference_IsDigested(t *testing.T) {
	// Test reference with tag (not digested)
	ar, err := NewArtifactReference("quay.io/podman/machine-os:5.1")
	require.NoError(t, err)
	assert.False(t, ar.IsDigested())

	// Test reference with digest (digested)
	ar, err = NewArtifactReference("quay.io/podman/machine-os@sha256:8b96f36deaf1d2713858eebd9ef2fee9610df8452fbd083bbfa7dca66d6fcd0b")
	require.NoError(t, err)
	assert.True(t, ar.IsDigested())

	// Test reference with latest tag (not digested)
	ar, err = NewArtifactReference("quay.io/podman/machine-os:latest")
	require.NoError(t, err)
	assert.False(t, ar.IsDigested())
}

func TestNewArtifactStorageReference_ValidReference(t *testing.T) {
	repo := "quay.io/podman/machine-os"
	tag := "5.1"
	ref := fmt.Sprintf("%s:%s", repo, tag)
	as, artifactDigest := setupNewStore(t, ref, nil, nil)

	// Test with a valid named reference - should find the artifact in the store
	asr, err := NewArtifactStorageReference(ref, as)
	assert.NoError(t, err)
	assert.NotNil(t, asr.Ref)
	assert.Equal(t, "quay.io/podman/machine-os:5.1", asr.Ref.String())
	assert.False(t, asr.IsDigested)
	assert.NotNil(t, asr.ArtifactFromStore)
	assert.Equal(t, "quay.io/podman/machine-os:5.1", asr.ArtifactFromStore.Name)

	// Lookup by Digest
	asr, err = NewArtifactStorageReference(fmt.Sprintf("%s@%s", repo, artifactDigest.String()), as)
	assert.NoError(t, err)
	assert.NotNil(t, asr.ArtifactFromStore)
	assert.True(t, asr.IsDigested)
	assert.NotNil(t, asr.ArtifactFromStore)
}

func TestNewArtifactStorageReference_AutoTagLatest(t *testing.T) {
	repoNameOnly := "quay.io/podman/machine-os"
	as, _ := setupNewStore(t, repoNameOnly, nil, nil)

	// Test with a reference without a tag (should auto-add :latest)
	asr, err := NewArtifactStorageReference(repoNameOnly, as)
	assert.NoError(t, err)
	assert.NotNil(t, asr.Ref)
	assert.Equal(t, fmt.Sprintf("%s:latest", repoNameOnly), asr.Ref.String())
	assert.False(t, asr.IsDigested)
}

func TestNewArtifactStorageReference_InvalidReference(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	// Create an artifact store
	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Test with an invalid reference that also doesn't exist in the store
	// This should fail both as a reference parse and as a store lookup
	_, err = NewArtifactStorageReference("nonexistent-digest-12345", as)
	assert.Error(t, err)
}

func TestNewArtifactStorageReference_EmptyString(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	// Create an artifact store
	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Test with empty string
	_, err = NewArtifactStorageReference("", as)
	assert.Error(t, err)
}

func TestStringToNamed(t *testing.T) {
	// Test valid named reference
	named, err := stringToNamed("quay.io/podman/machine-os:5.1")
	assert.NoError(t, err)
	assert.NotNil(t, named)
	assert.Equal(t, "quay.io/podman/machine-os:5.1", named.String())

	// Test reference without tag (should add :latest)
	named, err = stringToNamed("quay.io/podman/machine-os")
	assert.NoError(t, err)
	assert.NotNil(t, named)
	assert.Equal(t, "quay.io/podman/machine-os:latest", named.String())

	// Test reference with digest
	named, err = stringToNamed("quay.io/podman/machine-os@sha256:8b96f36deaf1d2713858eebd9ef2fee9610df8452fbd083bbfa7dca66d6fcd0b")
	assert.NoError(t, err)
	assert.NotNil(t, named)
	assert.Equal(t, "quay.io/podman/machine-os@sha256:8b96f36deaf1d2713858eebd9ef2fee9610df8452fbd083bbfa7dca66d6fcd0b", named.String())

	// Test invalid reference
	_, err = stringToNamed("invalid::reference")
	assert.Error(t, err)

	// Test empty string
	_, err = stringToNamed("")
	assert.Error(t, err)
}

func TestNewArtifactStore(t *testing.T) {
	// Test with valid absolute path
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	as, err := NewArtifactStore(storePath, sc)
	assert.NoError(t, err)
	assert.NotNil(t, as)
	assert.Equal(t, storePath, as.storePath)

	// Verify the index file was created
	indexPath := filepath.Join(storePath, "index.json")
	_, err = os.Stat(indexPath)
	assert.NoError(t, err)

	// Test with empty path
	_, err = NewArtifactStore("", sc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "store path cannot be empty")

	// Test with relative path
	_, err = NewArtifactStore("relative/path", sc)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be absolute")
}

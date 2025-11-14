package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	specV1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	libartTypes "go.podman.io/common/pkg/libartifact/types"
	"go.podman.io/image/v5/types"
	"go.step.sm/crypto/randutil"
)

// setupNewStore is a test helper and wrapper to helperAddArtifact. Use
// this approach when you don't care what populates the store in terms
// of the filenames.
func setupNewStore(t *testing.T, refName string, fileNames map[string]int, options *libartTypes.AddOptions) (*ArtifactStore, *digest.Digest) {
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	// Create the store first
	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	d := helperAddArtifact(t, as, refName, fileNames, options)
	require.NotEmpty(t, d)
	return as, d
}

// helperAddArtifact is a test helper that adds an artifact to the store.
// It creates temporary files with random content and adds them as blobs.
// fileNames maps filename to size in bytes of random content to generate.
// If options is nil, uses a default with ArtifactMIMEType set to "application/vnd.test+type".
func helperAddArtifact(t *testing.T, as *ArtifactStore, refName string, fileNames map[string]int, options *libartTypes.AddOptions) *digest.Digest {
	t.Helper()
	ctx := context.Background()

	// If options is nil, create default options
	if options == nil {
		options = &libartTypes.AddOptions{
			ArtifactMIMEType: "application/vnd.test+type",
		}
	}

	// if no specific files were passed, create a random file of 2k
	if fileNames == nil {
		filename, err := randutil.Alphanumeric(5)
		assert.NoError(t, err)
		fileNames = map[string]int{
			filename: 2,
		}
	}

	// Create artifact reference
	ref, err := NewArtifactReference(refName)
	require.NoError(t, err)

	// Create temporary files and artifact blobs
	tempDir := t.TempDir()
	blobs := make([]libartTypes.ArtifactBlob, 0, len(fileNames))

	for fileName, size := range fileNames {
		// Generate random content
		content := make([]byte, size)
		_, err := rand.Read(content)
		require.NoError(t, err)

		filePath := filepath.Join(tempDir, fileName)
		err = os.WriteFile(filePath, content, 0o644)
		require.NoError(t, err)

		blobs = append(blobs, libartTypes.ArtifactBlob{
			BlobFilePath: filePath,
			FileName:     fileName,
		})
	}

	// Add artifact
	artifactDigest, err := as.Add(ctx, ref, blobs, options)
	require.NoError(t, err)
	require.NotNil(t, artifactDigest)

	return artifactDigest
}

func TestArtifactStore_Add(t *testing.T) {
	ctx := context.Background()
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Add artifact using helper with nil options (uses default)
	fileNames := map[string]int{
		"testfile.txt": 1024,
	}

	refName := "quay.io/test/artifact:v1"
	artifactDigest := helperAddArtifact(t, as, refName, fileNames, nil)
	assert.NotEmpty(t, artifactDigest.String())

	// Verify artifact was added to the store
	artifacts, err := as.List(ctx)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1)

	// Verify artifact properties
	artifact := artifacts[0]
	assert.Equal(t, refName, artifact.Name)
	assert.Equal(t, "application/vnd.test+type", artifact.Manifest.ArtifactType)
	assert.Len(t, artifact.Manifest.Layers, 1)

	// Append another file to the same artifact
	appendFileNames := map[string]int{
		"appended.txt": 512,
	}
	appendOptions := &libartTypes.AddOptions{
		Append: true,
	}

	appendDigest := helperAddArtifact(t, as, refName, appendFileNames, appendOptions)
	assert.NotEmpty(t, appendDigest.String())

	// Verify artifact now has 2 layers
	artifacts, err = as.List(ctx)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1)

	artifact = artifacts[0]
	assert.Len(t, artifact.Manifest.Layers, 2)

	// Verify both files are present
	foundFiles := make(map[string]bool)
	for _, layer := range artifact.Manifest.Layers {
		title := layer.Annotations[specV1.AnnotationTitle]
		foundFiles[title] = true
	}
	assert.True(t, foundFiles["testfile.txt"])
	assert.True(t, foundFiles["appended.txt"])

	// Replace the artifact with a completely new one
	replaceFileNames := map[string]int{
		"replacement.bin": 2048,
	}
	replaceOptions := &libartTypes.AddOptions{
		Replace:          true,
		ArtifactMIMEType: "application/vnd.replaced+type",
	}

	replaceDigest := helperAddArtifact(t, as, refName, replaceFileNames, replaceOptions)
	assert.NotEmpty(t, replaceDigest.String())

	// Verify artifact was replaced with only the new file
	artifacts, err = as.List(ctx)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1)

	artifact = artifacts[0]
	assert.Len(t, artifact.Manifest.Layers, 1)
	assert.Equal(t, "application/vnd.replaced+type", artifact.Manifest.ArtifactType)

	// Verify only the replacement file is present
	assert.Equal(t, "replacement.bin", artifact.Manifest.Layers[0].Annotations[specV1.AnnotationTitle])
}

func TestArtifactStore_Add_MultipleFiles(t *testing.T) {
	ctx := context.Background()
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Add artifact with multiple files using helper with nil options (uses default)
	fileNames := map[string]int{
		"file1.txt": 512,
		"file2.bin": 1024,
		"file3.dat": 2048,
	}
	refName := "quay.io/test/multifile:v1"
	artifactDigest := helperAddArtifact(t, as, refName, fileNames, nil)
	assert.NotEmpty(t, artifactDigest.String())

	// Verify artifact was added to the store
	artifacts, err := as.List(ctx)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1)

	// Verify artifact has 3 layers
	artifact := artifacts[0]
	assert.Equal(t, refName, artifact.Name)
	assert.Equal(t, "application/vnd.test+type", artifact.Manifest.ArtifactType)
	assert.Len(t, artifact.Manifest.Layers, 3)

	// Verify all file names are present in layer annotations
	foundFiles := make(map[string]bool)
	for _, layer := range artifact.Manifest.Layers {
		title := layer.Annotations[specV1.AnnotationTitle]
		foundFiles[title] = true
	}
	assert.True(t, foundFiles["file1.txt"], "file1.txt should be present")
	assert.True(t, foundFiles["file2.bin"], "file2.bin should be present")
	assert.True(t, foundFiles["file3.dat"], "file3.dat should be present")

	// Verify layer sizes match expected sizes
	for _, layer := range artifact.Manifest.Layers {
		title := layer.Annotations[specV1.AnnotationTitle]
		expectedSize := int64(fileNames[title])
		assert.Equal(t, expectedSize, layer.Size, "Layer size for %s should match", title)
	}
}

func TestArtifactStore_Add_CustomMIMEType(t *testing.T) {
	ctx := context.Background()
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Add artifact with custom MIME type
	fileNames := map[string]int{
		"config.json": 256,
	}
	options := &libartTypes.AddOptions{
		ArtifactMIMEType: "application/vnd.custom+json",
	}

	artifactDigest := helperAddArtifact(t, as, "quay.io/test/custom:v1", fileNames, options)
	assert.NotEmpty(t, artifactDigest.String())

	// Verify artifact uses custom MIME type
	artifacts, err := as.List(ctx)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1)

	artifact := artifacts[0]
	assert.Equal(t, "application/vnd.custom+json", artifact.Manifest.ArtifactType)
}

func TestArtifactStore_Remove(t *testing.T) {
	ctx := context.Background()
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Add multiple artifacts
	fileNames1 := map[string]int{
		"file1.txt": 1024,
	}
	helperAddArtifact(t, as, "quay.io/test/artifact1:v1", fileNames1, nil)

	fileNames2 := map[string]int{
		"file2.txt": 2048,
	}
	helperAddArtifact(t, as, "quay.io/test/artifact2:v1", fileNames2, nil)

	// Verify both artifacts exist
	artifacts, err := as.List(ctx)
	require.NoError(t, err)
	assert.Len(t, artifacts, 2)

	// Get the first artifact and create a reference with it
	artifact1 := artifacts[0]
	digest1, err := artifact1.GetDigest()
	require.NoError(t, err)

	// Remove the first artifact by digest
	ref, err := NewArtifactStorageReference(digest1.Encoded(), as)
	require.NoError(t, err)

	removedDigest, err := as.Remove(ctx, ref)
	require.NoError(t, err)
	require.NotNil(t, removedDigest)
	assert.NotEmpty(t, removedDigest.String())

	// Verify only one artifact remains
	artifacts, err = as.List(ctx)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1)

	// Get the remaining artifact
	artifact2 := artifacts[0]
	digest2, err := artifact2.GetDigest()
	require.NoError(t, err)

	// Remove the second artifact by digest
	ref2, err := NewArtifactStorageReference(digest2.Encoded(), as)
	require.NoError(t, err)

	removedDigest2, err := as.Remove(ctx, ref2)
	require.NoError(t, err)
	require.NotNil(t, removedDigest2)

	// Verify store is now empty
	artifacts, err = as.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, artifacts)
}

func TestArtifactStore_Inspect(t *testing.T) {
	ctx := context.Background()
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Add an artifact with multiple files
	fileNames := map[string]int{
		"file1.txt": 512,
		"file2.bin": 1024,
		"file3.dat": 2048,
	}
	options := &libartTypes.AddOptions{
		ArtifactMIMEType: "application/vnd.test+type",
		Annotations: map[string]string{
			"custom.annotation": "test-value",
		},
	}

	refName := "quay.io/test/inspect:v1"
	helperAddArtifact(t, as, refName, fileNames, options)

	// Get the artifact from the list
	artifacts, err := as.List(ctx)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	// Create a reference using the artifact's digest
	artifact := artifacts[0]
	digest, err := artifact.GetDigest()
	require.NoError(t, err)

	ref, err := NewArtifactStorageReference(digest.Encoded(), as)
	require.NoError(t, err)

	// Inspect the artifact
	inspectedArtifact, err := as.Inspect(ctx, ref)
	require.NoError(t, err)
	require.NotNil(t, inspectedArtifact)

	// Verify inspected artifact properties
	assert.Equal(t, refName, inspectedArtifact.Name)
	assert.Equal(t, "application/vnd.test+type", inspectedArtifact.Manifest.ArtifactType)
	assert.Len(t, inspectedArtifact.Manifest.Layers, 3)

	// Verify custom annotation is present
	assert.Equal(t, "test-value", inspectedArtifact.Manifest.Annotations["custom.annotation"])

	// Verify all files are present in layers
	foundFiles := make(map[string]int64)
	for _, layer := range inspectedArtifact.Manifest.Layers {
		title := layer.Annotations[specV1.AnnotationTitle]
		foundFiles[title] = layer.Size
	}
	assert.Equal(t, int64(512), foundFiles["file1.txt"])
	assert.Equal(t, int64(1024), foundFiles["file2.bin"])
	assert.Equal(t, int64(2048), foundFiles["file3.dat"])

	// Verify total size calculation
	totalSize := inspectedArtifact.TotalSizeBytes()
	expectedTotal := int64(512 + 1024 + 2048)
	assert.Equal(t, expectedTotal, totalSize)
}

func TestArtifactStore_Extract(t *testing.T) {
	ctx := context.Background()
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Add an artifact with multiple files
	fileNames := map[string]int{
		"file1.txt": 512,
		"file2.bin": 1024,
		"file3.dat": 2048,
	}

	helperAddArtifact(t, as, "quay.io/test/extract:v1", fileNames, nil)

	// Get the artifact from the list
	artifacts, err := as.List(ctx)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	// Create a reference using the artifact's digest
	artifact := artifacts[0]
	digest, err := artifact.GetDigest()
	require.NoError(t, err)

	ref, err := NewArtifactStorageReference(digest.Encoded(), as)
	require.NoError(t, err)

	// Extract to a directory
	extractDir := t.TempDir()
	err = as.Extract(ctx, ref, extractDir, &libartTypes.ExtractOptions{})
	require.NoError(t, err)

	// Verify all files were extracted
	extractedFile1 := filepath.Join(extractDir, "file1.txt")
	extractedFile2 := filepath.Join(extractDir, "file2.bin")
	extractedFile3 := filepath.Join(extractDir, "file3.dat")

	stat1, err := os.Stat(extractedFile1)
	require.NoError(t, err)
	assert.Equal(t, int64(512), stat1.Size())

	stat2, err := os.Stat(extractedFile2)
	require.NoError(t, err)
	assert.Equal(t, int64(1024), stat2.Size())

	stat3, err := os.Stat(extractedFile3)
	require.NoError(t, err)
	assert.Equal(t, int64(2048), stat3.Size())

	// Verify file contents are not empty (random data was written)
	content1, err := os.ReadFile(extractedFile1)
	require.NoError(t, err)
	assert.Len(t, content1, 512)

	content2, err := os.ReadFile(extractedFile2)
	require.NoError(t, err)
	assert.Len(t, content2, 1024)

	content3, err := os.ReadFile(extractedFile3)
	require.NoError(t, err)
	assert.Len(t, content3, 2048)
}

func TestArtifactStore_Extract_SingleFile(t *testing.T) {
	ctx := context.Background()
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Add an artifact with multiple files
	fileNames := map[string]int{
		"file1.txt": 512,
		"file2.bin": 1024,
	}

	helperAddArtifact(t, as, "quay.io/test/extract-single:v1", fileNames, nil)

	// Get the artifact from the list
	artifacts, err := as.List(ctx)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	// Create a reference using the artifact's digest
	artifact := artifacts[0]
	digest, err := artifact.GetDigest()
	require.NoError(t, err)

	ref, err := NewArtifactStorageReference(digest.Encoded(), as)
	require.NoError(t, err)

	// Extract only one file by title
	extractDir := t.TempDir()
	err = as.Extract(ctx, ref, extractDir, &libartTypes.ExtractOptions{
		FilterBlobOptions: libartTypes.FilterBlobOptions{
			Title: "file1.txt",
		},
	})
	require.NoError(t, err)

	// Verify only file1.txt was extracted
	extractedFile1 := filepath.Join(extractDir, "file1.txt")
	extractedFile2 := filepath.Join(extractDir, "file2.bin")

	stat1, err := os.Stat(extractedFile1)
	require.NoError(t, err)
	assert.Equal(t, int64(512), stat1.Size())

	_, err = os.Stat(extractedFile2)
	assert.True(t, os.IsNotExist(err))
}

func TestArtifactStore_List_Multiple(t *testing.T) {
	ctx := context.Background()
	storePath := filepath.Join(t.TempDir(), "store")
	sc := &types.SystemContext{}

	as, err := NewArtifactStore(storePath, sc)
	require.NoError(t, err)
	require.NotNil(t, as)

	// Verify empty store returns empty list
	artifacts, err := as.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, artifacts)

	// Add multiple artifacts with different configurations
	fileNames1 := map[string]int{
		"file1.txt": 512,
	}
	helperAddArtifact(t, as, "quay.io/test/artifact1:v1", fileNames1, nil)

	fileNames2 := map[string]int{
		"file2a.bin": 1024,
		"file2b.dat": 2048,
	}
	options2 := &libartTypes.AddOptions{
		ArtifactMIMEType: "application/vnd.custom+type",
	}
	helperAddArtifact(t, as, "quay.io/test/artifact2:v2", fileNames2, options2)

	fileNames3 := map[string]int{
		"file3.json": 256,
	}
	helperAddArtifact(t, as, "docker.io/library/artifact3:latest", fileNames3, nil)

	// List all artifacts
	artifacts, err = as.List(ctx)
	require.NoError(t, err)
	assert.Len(t, artifacts, 3)

	// Create a map of artifact names for easy lookup
	artifactMap := make(map[string]*Artifact)
	for _, artifact := range artifacts {
		artifactMap[artifact.Name] = artifact
	}

	// Verify first artifact
	artifact1, exists := artifactMap["quay.io/test/artifact1:v1"]
	require.True(t, exists)
	assert.Equal(t, "application/vnd.test+type", artifact1.Manifest.ArtifactType)
	assert.Len(t, artifact1.Manifest.Layers, 1)
	assert.Equal(t, int64(512), artifact1.TotalSizeBytes())

	// Verify second artifact
	artifact2, exists := artifactMap["quay.io/test/artifact2:v2"]
	require.True(t, exists)
	assert.Equal(t, "application/vnd.custom+type", artifact2.Manifest.ArtifactType)
	assert.Len(t, artifact2.Manifest.Layers, 2)
	assert.Equal(t, int64(3072), artifact2.TotalSizeBytes())

	// Verify third artifact
	artifact3, exists := artifactMap["docker.io/library/artifact3:latest"]
	require.True(t, exists)
	assert.Equal(t, "application/vnd.test+type", artifact3.Manifest.ArtifactType)
	assert.Len(t, artifact3.Manifest.Layers, 1)
	assert.Equal(t, int64(256), artifact3.TotalSizeBytes())

	// Verify all artifacts have valid digests
	for _, artifact := range artifacts {
		digest, err := artifact.GetDigest()
		require.NoError(t, err)
		assert.NotEmpty(t, digest.String())
	}
}

func TestDetermineBlobMIMEType_FromFile(t *testing.T) {
	tempDir := t.TempDir()

	// Test with plain text file
	textFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(textFile, []byte("Hello, World!"), 0o644)
	require.NoError(t, err)

	blob := libartTypes.ArtifactBlob{
		BlobFilePath: textFile,
		FileName:     "test.txt",
	}

	reader, mimeType, err := determineBlobMIMEType(blob)
	require.NoError(t, err)
	assert.Nil(t, reader)
	assert.Equal(t, "text/plain; charset=utf-8", mimeType)

	// Test with JSON file
	jsonFile := filepath.Join(tempDir, "test.json")
	jsonContent := []byte(`{"key": "value", "number": 123}`)
	err = os.WriteFile(jsonFile, jsonContent, 0o644)
	require.NoError(t, err)

	blob = libartTypes.ArtifactBlob{
		BlobFilePath: jsonFile,
		FileName:     "test.json",
	}

	reader, mimeType, err = determineBlobMIMEType(blob)
	require.NoError(t, err)
	assert.Nil(t, reader)
	assert.Equal(t, "text/plain; charset=utf-8", mimeType)

	// Test with binary file
	binaryFile := filepath.Join(tempDir, "test.bin")
	binaryContent := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46}
	err = os.WriteFile(binaryFile, binaryContent, 0o644)
	require.NoError(t, err)

	blob = libartTypes.ArtifactBlob{
		BlobFilePath: binaryFile,
		FileName:     "test.bin",
	}

	reader, mimeType, err = determineBlobMIMEType(blob)
	require.NoError(t, err)
	assert.Nil(t, reader)
	assert.Equal(t, "image/jpeg", mimeType)
}

func TestDetermineBlobMIMEType_FromReader(t *testing.T) {
	// Test with plain text reader
	textContent := "This is plain text content"
	blob := libartTypes.ArtifactBlob{
		BlobReader: strings.NewReader(textContent),
		FileName:   "test.txt",
	}

	reader, mimeType, err := determineBlobMIMEType(blob)
	require.NoError(t, err)
	require.NotNil(t, reader)
	assert.Equal(t, "text/plain; charset=utf-8", mimeType)

	// Verify the reader still has all the content
	content, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, textContent, string(content))

	// Test with HTML content
	htmlContent := "<!DOCTYPE html><html><body>Test</body></html>"
	blob = libartTypes.ArtifactBlob{
		BlobReader: strings.NewReader(htmlContent),
		FileName:   "test.html",
	}

	reader, mimeType, err = determineBlobMIMEType(blob)
	require.NoError(t, err)
	require.NotNil(t, reader)
	assert.Equal(t, "text/html; charset=utf-8", mimeType)

	// Test with binary content
	binaryContent := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	blob = libartTypes.ArtifactBlob{
		BlobReader: bytes.NewReader(binaryContent),
		FileName:   "test.png",
	}

	reader, mimeType, err = determineBlobMIMEType(blob)
	require.NoError(t, err)
	require.NotNil(t, reader)
	assert.Equal(t, "image/png", mimeType)
}

func TestDetermineBlobMIMEType_SmallFile(t *testing.T) {
	tempDir := t.TempDir()

	// Test with file smaller than 512 bytes
	smallFile := filepath.Join(tempDir, "small.txt")
	smallContent := []byte("Small")
	err := os.WriteFile(smallFile, smallContent, 0o644)
	require.NoError(t, err)

	blob := libartTypes.ArtifactBlob{
		BlobFilePath: smallFile,
		FileName:     "small.txt",
	}

	reader, mimeType, err := determineBlobMIMEType(blob)
	require.NoError(t, err)
	assert.Nil(t, reader)
	assert.Equal(t, "text/plain; charset=utf-8", mimeType)
}

func TestDetermineBlobMIMEType_Errors(t *testing.T) {
	// Test with neither file path nor reader
	blob := libartTypes.ArtifactBlob{
		FileName: "test.txt",
	}

	_, _, err := determineBlobMIMEType(blob)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Artifact.BlobFile or Artifact.BlobReader must be provided")

	// Test with both file path and reader
	blob = libartTypes.ArtifactBlob{
		BlobFilePath: "/tmp/test.txt",
		BlobReader:   strings.NewReader("content"),
		FileName:     "test.txt",
	}

	_, _, err = determineBlobMIMEType(blob)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Artifact.BlobFile or Artifact.BlobReader must be provided")

	// Test with non-existent file
	blob = libartTypes.ArtifactBlob{
		BlobFilePath: "/nonexistent/file.txt",
		FileName:     "file.txt",
	}

	_, _, err = determineBlobMIMEType(blob)
	require.Error(t, err)
}

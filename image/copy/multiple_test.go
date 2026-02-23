package copy

import (
	"os"
	"path/filepath"
	"testing"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	internalManifest "go.podman.io/image/v5/internal/manifest"
	"go.podman.io/image/v5/pkg/compression"
)

// Test `instanceOpCopy` cases.
func TestPrepareCopyInstancesforInstanceCopyCopy(t *testing.T) {
	validManifest, err := os.ReadFile(filepath.Join("..", "internal", "manifest", "testdata", "oci1.index.zstd-selection.json"))
	require.NoError(t, err)
	list, err := internalManifest.ListFromBlob(validManifest, internalManifest.GuessMIMEType(validManifest))
	require.NoError(t, err)

	// Test CopyAllImages
	sourceInstances := []digest.Digest{
		digest.Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		digest.Digest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
	}

	instancesToCopy, err := prepareInstanceCopies(list, sourceInstances, &Options{})
	require.NoError(t, err)
	compare := []instanceOp{}

	for _, instance := range sourceInstances {
		compare = append(compare, instanceOp{
			op:           instanceOpCopy,
			sourceDigest: instance, copyForceCompressionFormat: false,
		})
	}
	assert.Equal(t, instancesToCopy, compare)

	// Test CopySpecificImages where selected instance is sourceInstances[1]
	instancesToCopy, err = prepareInstanceCopies(list, sourceInstances, &Options{Instances: []digest.Digest{sourceInstances[1]}, ImageListSelection: CopySpecificImages})
	require.NoError(t, err)
	compare = []instanceOp{{
		op:           instanceOpCopy,
		sourceDigest: sourceInstances[1],
	}}
	assert.Equal(t, instancesToCopy, compare)

	// Test CopySpecificImages with StripSparseManifestList where selected instance is sourceInstances[1]
	instancesToCopy, err = prepareInstanceCopies(list, sourceInstances, &Options{
		Instances:                []digest.Digest{sourceInstances[1]},
		ImageListSelection:       CopySpecificImages,
		SparseManifestListAction: StripSparseManifestList,
	})
	require.NoError(t, err)
	// Should have 1 copy operation followed by 2 delete operations (for indices 0 and 2)
	expected := []instanceOp{
		{
			op:           instanceOpCopy,
			sourceDigest: sourceInstances[1],
		},
		{
			op:          instanceOpDelete,
			deleteIndex: 2, // Delete from highest to lowest
		},
		{
			op:          instanceOpDelete,
			deleteIndex: 0,
		},
	}
	assert.Equal(t, expected, instancesToCopy)

	_, err = prepareInstanceCopies(list, sourceInstances, &Options{Instances: []digest.Digest{sourceInstances[1]}, ImageListSelection: CopySpecificImages, ForceCompressionFormat: true})
	require.EqualError(t, err, "cannot use ForceCompressionFormat with undefined default compression format")
}

// Test `instanceOpClone` cases.
func TestPrepareCopyInstancesforInstanceCopyClone(t *testing.T) {
	validManifest, err := os.ReadFile(filepath.Join("..", "internal", "manifest", "testdata", "oci1.index.zstd-selection.json"))
	require.NoError(t, err)
	list, err := internalManifest.ListFromBlob(validManifest, internalManifest.GuessMIMEType(validManifest))
	require.NoError(t, err)

	// Prepare option for `instanceOpClone` case.
	ensureCompressionVariantsExist := []OptionCompressionVariant{{Algorithm: compression.Zstd}}

	sourceInstances := []digest.Digest{
		digest.Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		digest.Digest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
	}

	// CopySpecificImage must fail with error
	_, err = prepareInstanceCopies(list, sourceInstances, &Options{
		EnsureCompressionVariantsExist: ensureCompressionVariantsExist,
		Instances:                      []digest.Digest{sourceInstances[1]},
		ImageListSelection:             CopySpecificImages,
	})
	require.EqualError(t, err, "EnsureCompressionVariantsExist is not implemented for CopySpecificImages")

	// Test copying all images with replication
	instancesToCopy, err := prepareInstanceCopies(list, sourceInstances, &Options{EnsureCompressionVariantsExist: ensureCompressionVariantsExist})
	require.NoError(t, err)

	// Following test ensures
	// * Still copy gzip variants if they exist in the original
	// * Not create new Zstd variants if they exist in the original.

	// We created a list of three instances `sourceInstances` and since in oci1.index.zstd-selection.json
	// amd64 already has a zstd instance i.e sourceInstance[1] so it should not create replication for
	// `sourceInstance[0]` and `sourceInstance[1]` but should do it for `sourceInstance[2]` for `arm64`
	// and still copy `sourceInstance[2]`.
	expectedResponse := []simplerInstanceCopy{}
	for _, instance := range sourceInstances {
		expectedResponse = append(expectedResponse, simplerInstanceCopy{
			op:           instanceOpCopy,
			sourceDigest: instance,
		})
		// If its `arm64` and sourceDigest[2] , expect a clone to happen
		if instance == sourceInstances[2] {
			expectedResponse = append(expectedResponse, simplerInstanceCopy{op: instanceOpClone, sourceDigest: instance, cloneCompressionVariant: "zstd", clonePlatform: "arm64-linux-"})
		}
	}
	actualResponse := convertInstanceCopyToSimplerInstanceCopy(instancesToCopy)
	assert.Equal(t, expectedResponse, actualResponse)

	// Test option with multiple copy request for same compression format.
	// The above expectation should stay the same, if ensureCompressionVariantsExist requests zstd twice.
	ensureCompressionVariantsExist = []OptionCompressionVariant{{Algorithm: compression.Zstd}, {Algorithm: compression.Zstd}}
	instancesToCopy, err = prepareInstanceCopies(list, sourceInstances, &Options{EnsureCompressionVariantsExist: ensureCompressionVariantsExist})
	require.NoError(t, err)
	expectedResponse = []simplerInstanceCopy{}
	for _, instance := range sourceInstances {
		expectedResponse = append(expectedResponse, simplerInstanceCopy{
			op:           instanceOpCopy,
			sourceDigest: instance,
		})
		// If its `arm64` and sourceDigest[2] , expect a clone to happen
		if instance == sourceInstances[2] {
			expectedResponse = append(expectedResponse, simplerInstanceCopy{op: instanceOpClone, sourceDigest: instance, cloneCompressionVariant: "zstd", clonePlatform: "arm64-linux-"})
		}
	}
	actualResponse = convertInstanceCopyToSimplerInstanceCopy(instancesToCopy)
	assert.Equal(t, expectedResponse, actualResponse)

	// Add same instance twice but clone must appear only once.
	ensureCompressionVariantsExist = []OptionCompressionVariant{{Algorithm: compression.Zstd}}
	sourceInstances = []digest.Digest{
		digest.Digest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
		digest.Digest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
	}
	instancesToCopy, err = prepareInstanceCopies(list, sourceInstances, &Options{EnsureCompressionVariantsExist: ensureCompressionVariantsExist})
	require.NoError(t, err)
	// two copies but clone should happen only once
	numberOfCopyClone := 0
	for _, instance := range instancesToCopy {
		if instance.op == instanceOpClone {
			numberOfCopyClone++
		}
	}
	assert.Equal(t, 1, numberOfCopyClone)
}

// simpler version of `instanceOp` for testing where fields are string
// instead of pointer
type simplerInstanceCopy struct {
	op           instanceOpKind
	sourceDigest digest.Digest

	// Fields which can be used by callers when operation
	// is `instanceOpClone`
	cloneCompressionVariant string
	clonePlatform           string
	cloneAnnotations        map[string]string
}

func convertInstanceCopyToSimplerInstanceCopy(copies []instanceOp) []simplerInstanceCopy {
	res := []simplerInstanceCopy{}
	for _, instance := range copies {
		compression := ""
		platform := ""
		compression = instance.cloneCompressionVariant.Algorithm.Name()
		if instance.clonePlatform != nil {
			platform = instance.clonePlatform.Architecture + "-" + instance.clonePlatform.OS + "-" + instance.clonePlatform.Variant
		}
		res = append(res, simplerInstanceCopy{
			op:                      instance.op,
			sourceDigest:            instance.sourceDigest,
			cloneCompressionVariant: compression,
			clonePlatform:           platform,
			cloneAnnotations:        instance.cloneAnnotations,
		})
	}
	return res
}

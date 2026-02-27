package copy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/directory"
	internalManifest "go.podman.io/image/v5/internal/manifest"
	"go.podman.io/image/v5/pkg/compression"
)

const (
	// Test manifest files (relative to ../internal/manifest/testdata/)
	ociManifestFile  = "ociv1.manifest.json"
	ociIndexZstdFile = "oci1.index.zstd-selection.json"
)

// Test `instanceOpCopy` cases.
func TestPrepareCopyInstancesforInstanceCopyCopy(t *testing.T) {
	validManifest, err := os.ReadFile(filepath.Join("..", "internal", "manifest", "testdata", ociIndexZstdFile))
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
	validManifest, err := os.ReadFile(filepath.Join("..", "internal", "manifest", "testdata", ociIndexZstdFile))
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

// TestStripOnlyListSignaturesValidation tests the validation logic for StripOnlyListSignatures
// by actually calling copy.Image() with various option combinations.
func TestStripOnlyListSignaturesValidation(t *testing.T) {
	tests := []struct {
		name          string
		manifestFile  string // Relative to testdata directory
		options       *Options
		expectedError string
	}{
		{
			name:         "Invalid: StripOnlyListSignatures with single image (not manifest list)",
			manifestFile: ociManifestFile,
			options: &Options{
				ImageListSelection:       CopySpecificImages,
				SparseManifestListAction: StripSparseManifestList,
				StripOnlyListSignatures:  true,
			},
			expectedError: "StripOnlyListSignatures can only be used with manifest lists, not single images",
		},
		{
			name:         "Invalid: StripOnlyListSignatures with CopySystemImage",
			manifestFile: ociIndexZstdFile,
			options: &Options{
				ImageListSelection:       CopySystemImage,
				SparseManifestListAction: StripSparseManifestList,
				StripOnlyListSignatures:  true,
			},
			expectedError: "StripOnlyListSignatures can only be used with CopySpecificImages and SparseManifestListAction=StripSparseManifestList, not with CopySystemImage",
		},
		{
			name:         "Invalid: StripOnlyListSignatures with CopyAllImages",
			manifestFile: ociIndexZstdFile,
			options: &Options{
				ImageListSelection:       CopyAllImages,
				SparseManifestListAction: StripSparseManifestList,
				StripOnlyListSignatures:  true,
			},
			expectedError: "StripOnlyListSignatures can only be used with CopySpecificImages, not CopyAllImages",
		},
		{
			name:         "Invalid: StripOnlyListSignatures without StripSparseManifestList",
			manifestFile: ociIndexZstdFile,
			options: &Options{
				ImageListSelection:       CopySpecificImages,
				SparseManifestListAction: KeepSparseManifestList,
				StripOnlyListSignatures:  true,
			},
			expectedError: "StripOnlyListSignatures requires SparseManifestListAction=StripSparseManifestList",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load the appropriate manifest for this test case
			manifest, err := os.ReadFile(filepath.Join("..", "internal", "manifest", "testdata", tt.manifestFile))
			require.NoError(t, err)

			// Set up source directory with the manifest
			srcDir := t.TempDir()
			srcManifestPath := filepath.Join(srcDir, "manifest.json")
			require.NoError(t, os.WriteFile(srcManifestPath, manifest, 0644))

			// Set up destination directory
			destDir := t.TempDir()

			// Create source and destination references
			// Note: We use directory transport for simplicity, even though copy.Image
			// will fail later in the process. The validation we're testing happens
			// early in copy.Image() before it tries to actually copy data.
			srcRef, err := directory.NewReference(srcDir)
			require.NoError(t, err)
			destRef, err := directory.NewReference(destDir)
			require.NoError(t, err)

			// Call the real copy.Image() function
			_, err = Image(context.Background(), nil, destRef, srcRef, tt.options)

			// Verify the error matches expectations (all test cases in this function are invalid)
			require.Error(t, err, "Expected validation error from copy.Image()")
			assert.Equal(t, tt.expectedError, err.Error())
		})
	}
}

// TestStripSparseManifestListRequiresSignatureHandling tests that when using
// StripSparseManifestList with a signed manifest list, the user must explicitly
// choose how to handle signatures via RemoveSignatures or StripOnlyListSignatures.
func TestStripSparseManifestListRequiresSignatureHandling(t *testing.T) {
	// Load a manifest list
	manifest, err := os.ReadFile(filepath.Join("..", "internal", "manifest", "testdata", ociIndexZstdFile))
	require.NoError(t, err)

	tests := []struct {
		name          string
		options       *Options
		addSignature  bool
		expectedError string
	}{
		{
			name: "Valid: StripSparseManifestList with signed manifest + RemoveSignatures",
			options: &Options{
				ImageListSelection:       CopySpecificImages,
				Instances:                []digest.Digest{digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
				SparseManifestListAction: StripSparseManifestList,
				RemoveSignatures:         true,
			},
			addSignature:  true,
			expectedError: "",
		},
		{
			name: "Valid: StripSparseManifestList with signed manifest + StripOnlyListSignatures",
			options: &Options{
				ImageListSelection:       CopySpecificImages,
				Instances:                []digest.Digest{digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
				SparseManifestListAction: StripSparseManifestList,
				StripOnlyListSignatures:  true,
			},
			addSignature:  true,
			expectedError: "",
		},
		{
			name: "Invalid: StripSparseManifestList with signed manifest without signature handling",
			options: &Options{
				ImageListSelection:       CopySpecificImages,
				Instances:                []digest.Digest{digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
				SparseManifestListAction: StripSparseManifestList,
			},
			addSignature:  true,
			expectedError: "SparseManifestListAction.StripSparseManifestList will modify the signed manifest list; use RemoveSignatures to remove all signatures, or StripOnlyListSignatures to strip only the list signature while preserving per-instance signatures",
		},
		{
			name: "Valid: StripSparseManifestList with unsigned manifest (no signature handling needed)",
			options: &Options{
				ImageListSelection:       CopySpecificImages,
				Instances:                []digest.Digest{digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
				SparseManifestListAction: StripSparseManifestList,
			},
			addSignature:  false,
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up source directory with the manifest
			srcDir := t.TempDir()
			srcManifestPath := filepath.Join(srcDir, "manifest.json")
			require.NoError(t, os.WriteFile(srcManifestPath, manifest, 0644))

			// Add a signature file if requested
			if tt.addSignature {
				// For directory transport, signatures are stored as "signature-1", "signature-2", etc.
				// Copy an existing signature file from testdata
				existingSignature, err := os.ReadFile(filepath.Join("..", "internal", "signature", "testdata", "simple.signature"))
				require.NoError(t, err)
				signaturePath := filepath.Join(srcDir, "signature-1")
				require.NoError(t, os.WriteFile(signaturePath, existingSignature, 0644))
			}

			// Set up destination directory
			destDir := t.TempDir()

			// Create source and destination references
			srcRef, err := directory.NewReference(srcDir)
			require.NoError(t, err)
			destRef, err := directory.NewReference(destDir)
			require.NoError(t, err)

			// Call the real copy.Image() function
			_, err = Image(context.Background(), nil, destRef, srcRef, tt.options)

			// Verify the error matches expectations
			if tt.expectedError != "" {
				require.Error(t, err, "Expected validation error from copy.Image()")
				assert.Equal(t, tt.expectedError, err.Error())
			} else {
				// Note: The copy may fail for other reasons (missing blobs, etc.)
				// but should not fail with the signature handling error
				if err != nil {
					assert.NotContains(t, err.Error(), "will modify the signed manifest list")
				}
			}
		})
	}
}

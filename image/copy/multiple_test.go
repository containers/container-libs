package copy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	internalManifest "go.podman.io/image/v5/internal/manifest"
	"go.podman.io/image/v5/pkg/compression"
)

// Test `instanceCopyCopy` cases.
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
	compare := []instanceCopy{}

	for _, instance := range sourceInstances {
		compare = append(compare, instanceCopy{
			op:           instanceCopyCopy,
			sourceDigest: instance, copyForceCompressionFormat: false,
		})
	}
	assert.Equal(t, instancesToCopy, compare)

	// Test CopySpecificImages where selected instance is sourceInstances[1]
	instancesToCopy, err = prepareInstanceCopies(list, sourceInstances, &Options{Instances: []digest.Digest{sourceInstances[1]}, ImageListSelection: CopySpecificImages})
	require.NoError(t, err)
	compare = []instanceCopy{{
		op:           instanceCopyCopy,
		sourceDigest: sourceInstances[1],
	}}
	assert.Equal(t, instancesToCopy, compare)

	_, err = prepareInstanceCopies(list, sourceInstances, &Options{Instances: []digest.Digest{sourceInstances[1]}, ImageListSelection: CopySpecificImages, ForceCompressionFormat: true})
	require.EqualError(t, err, "cannot use ForceCompressionFormat with undefined default compression format")
}

// Test `instanceCopyClone` cases.
func TestPrepareCopyInstancesforInstanceCopyClone(t *testing.T) {
	validManifest, err := os.ReadFile(filepath.Join("..", "internal", "manifest", "testdata", "oci1.index.zstd-selection.json"))
	require.NoError(t, err)
	list, err := internalManifest.ListFromBlob(validManifest, internalManifest.GuessMIMEType(validManifest))
	require.NoError(t, err)

	// Prepare option for `instanceCopyClone` case.
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
			op:           instanceCopyCopy,
			sourceDigest: instance,
		})
		// If its `arm64` and sourceDigest[2] , expect a clone to happen
		if instance == sourceInstances[2] {
			expectedResponse = append(expectedResponse, simplerInstanceCopy{op: instanceCopyClone, sourceDigest: instance, cloneCompressionVariant: "zstd", clonePlatform: "arm64-linux-"})
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
			op:           instanceCopyCopy,
			sourceDigest: instance,
		})
		// If its `arm64` and sourceDigest[2] , expect a clone to happen
		if instance == sourceInstances[2] {
			expectedResponse = append(expectedResponse, simplerInstanceCopy{op: instanceCopyClone, sourceDigest: instance, cloneCompressionVariant: "zstd", clonePlatform: "arm64-linux-"})
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
		if instance.op == instanceCopyClone {
			numberOfCopyClone++
		}
	}
	assert.Equal(t, 1, numberOfCopyClone)
}

// simpler version of `instanceCopy` for testing where fields are string
// instead of pointer
type simplerInstanceCopy struct {
	op           instanceCopyKind
	sourceDigest digest.Digest

	// Fields which can be used by callers when operation
	// is `instanceCopyClone`
	cloneCompressionVariant string
	clonePlatform           string
	cloneAnnotations        map[string]string
}

func convertInstanceCopyToSimplerInstanceCopy(copies []instanceCopy) []simplerInstanceCopy {
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

// TestDetermineSpecificImages tests the platform-based and digest-based instance selection,
// including multi-compression scenarios and variant handling
func TestDetermineSpecificImages(t *testing.T) {
	// Test manifest files
	const (
		index                    = "ociv1.image.index.json"
		indexWithZstdCompression = "oci1.index.zstd-selection.json"
		indexWithVariants        = "ocilist-variants.json"
	)

	// Digests from ociv1.image.index.json
	ppc64leDigest := digest.Digest("sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f")
	amd64Digest := digest.Digest("sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270")

	// Digests from oci1.index.zstd-selection.json
	amd64Digest1 := digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	amd64Digest2 := digest.Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	amd64Digest3 := digest.Digest("sha256:0000000000000000000000000000000000000000000000000000000000000000")
	arm64Digest1 := digest.Digest("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	arm64Digest2 := digest.Digest("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	s390xDigest := digest.Digest("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

	// Digests from ocilist-variants.json
	amd64VariantsDigest := digest.Digest("sha256:59eec8837a4d942cc19a52b8c09ea75121acc38114a2c68b98983ce9356b8610")
	armV7Digest := digest.Digest("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	armV6Digest1 := digest.Digest("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	armV6Digest2 := digest.Digest("sha256:f365626a556e58189fc21d099fc64603db0f440bff07f77c740989515c544a39")
	armUnrecognizedDigest := digest.Digest("sha256:bcf9771c0b505e68c65440474179592ffdfa98790eb54ffbf129969c5e429990")
	armNoVariantDigest := digest.Digest("sha256:c84b0a3a07b628bc4d62e5047d0f8dff80f7c00979e1e28a821a033ecda8fe53")

	tests := []struct {
		name              string
		manifestFile      string
		instances         []digest.Digest
		instancePlatforms []imgspecv1.Platform
		expectedDigests   []digest.Digest
		expectedError     string // if non-empty, error message should contain this string
	}{
		// Basic tests with single instance per platform
		{
			name:         "PlatformOnly",
			manifestFile: index,
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "ppc64le"},
			},
			expectedDigests: []digest.Digest{ppc64leDigest},
		},
		{
			name:            "DigestOnly",
			manifestFile:    "ociv1.image.index.json",
			instances:       []digest.Digest{amd64Digest},
			expectedDigests: []digest.Digest{amd64Digest},
		},
		{
			name:         "Combined",
			manifestFile: index,
			instances:    []digest.Digest{ppc64leDigest},
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "amd64"},
			},
			expectedDigests: []digest.Digest{ppc64leDigest, amd64Digest},
		},
		{
			name:         "NonExistentPlatform",
			manifestFile: index,
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "arm64"},
			},
			expectedError: "no instances found for platform",
		},
		{
			name:         "VariantNotSupported",
			manifestFile: index,
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "amd64", Variant: "v7"},
			},
			expectedError: "variant is not currently supported",
		},
		// Multi-compression tests - verify ALL instances are copied
		{
			name:         "MultipleCompressionVariants",
			manifestFile: indexWithZstdCompression,
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "amd64"},
			},
			expectedDigests: []digest.Digest{amd64Digest1, amd64Digest2, amd64Digest3},
		},
		{
			name:         "MultiplePlatformsWithMultipleInstances",
			manifestFile: indexWithZstdCompression,
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "amd64"},
				{OS: "linux", Architecture: "arm64"},
			},
			expectedDigests: []digest.Digest{amd64Digest1, amd64Digest2, amd64Digest3, arm64Digest1, arm64Digest2},
		},
		{
			name:         "CombinedDigestAndPlatformMultiCompression",
			manifestFile: indexWithZstdCompression,
			instances:    []digest.Digest{s390xDigest},
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "amd64"},
			},
			expectedDigests: []digest.Digest{s390xDigest, amd64Digest1, amd64Digest2, amd64Digest3},
		},
		{
			name:         "SingleInstancePlatform",
			manifestFile: indexWithZstdCompression,
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "s390x"},
			},
			expectedDigests: []digest.Digest{s390xDigest},
		},
		// Variant tests - verify ALL variants are copied when no variant specified
		{
			name:         "AllArmVariants",
			manifestFile: indexWithVariants,
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "arm"},
			},
			expectedDigests: []digest.Digest{armV7Digest, armV6Digest1, armV6Digest2, armUnrecognizedDigest, armNoVariantDigest},
		},
		{
			name:         "VariantSpecifiedShouldError",
			manifestFile: indexWithVariants,
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "arm", Variant: "v7"},
			},
			expectedError: "variant is not currently supported",
		},
		{
			name:         "MultipleArchitecturesIncludingVariants",
			manifestFile: indexWithVariants,
			instancePlatforms: []imgspecv1.Platform{
				{OS: "linux", Architecture: "amd64"},
				{OS: "linux", Architecture: "arm"},
			},
			expectedDigests: []digest.Digest{amd64VariantsDigest, armV7Digest, armV6Digest1, armV6Digest2, armUnrecognizedDigest, armNoVariantDigest},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validManifest, err := os.ReadFile(filepath.Join("..", "internal", "manifest", "testdata", tt.manifestFile))
			require.NoError(t, err)
			list, err := internalManifest.ListFromBlob(validManifest, internalManifest.GuessMIMEType(validManifest))
			require.NoError(t, err)

			options := &Options{
				Instances:         tt.instances,
				InstancePlatforms: tt.instancePlatforms,
			}
			specificImages, err := determineSpecificImages(options, list)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.expectedError)
				return
			}

			require.NoError(t, err)
			// Convert Set to slice for comparison
			actualDigests := slices.Collect(specificImages.All())

			assert.ElementsMatch(t, tt.expectedDigests, actualDigests)
		})
	}
}

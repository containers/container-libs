package copy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/internal/private"
	"go.podman.io/image/v5/pkg/compression"
	compressiontypes "go.podman.io/image/v5/pkg/compression/types"
	"go.podman.io/image/v5/types"
)

func TestUpdatedBlobInfoFromReuse(t *testing.T) {
	srcInfo := types.BlobInfo{
		Digest:               "sha256:6a5a5368e0c2d3e5909184fa28ddfd56072e7ff3ee9a945876f7eee5896ef5bb",
		Size:                 51354364,
		URLs:                 []string{"https://layer.url"},
		Annotations:          map[string]string{"test-annotation-2": "two"},
		MediaType:            imgspecv1.MediaTypeImageLayerGzip,
		CompressionOperation: types.Compress,    // Might be set by blobCacheSource.LayerInfosForCopy
		CompressionAlgorithm: &compression.Gzip, // Set e.g. in copyLayer
		// CryptoOperation is not set by LayerInfos()
	}

	for _, c := range []struct {
		reused   private.ReusedBlob
		expected types.BlobInfo
	}{
		{ // A straightforward reuse without substitution
			reused: private.ReusedBlob{
				Digest: "sha256:6a5a5368e0c2d3e5909184fa28ddfd56072e7ff3ee9a945876f7eee5896ef5bb",
				Size:   51354364,
				// CompressionOperation not set
				// CompressionAlgorithm not set
			},
			expected: types.BlobInfo{
				Digest:               "sha256:6a5a5368e0c2d3e5909184fa28ddfd56072e7ff3ee9a945876f7eee5896ef5bb",
				Size:                 51354364,
				URLs:                 nil,
				Annotations:          map[string]string{"test-annotation-2": "two"},
				MediaType:            imgspecv1.MediaTypeImageLayerGzip,
				CompressionOperation: types.Compress,    // Might be set by blobCacheSource.LayerInfosForCopy
				CompressionAlgorithm: &compression.Gzip, // Set e.g. in copyLayer
				// CryptoOperation is set to the zero value
			},
		},
		{ // Reuse with substitution
			reused: private.ReusedBlob{
				Digest:                 "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Size:                   513543640,
				CompressionOperation:   types.Decompress,
				CompressionAlgorithm:   nil,
				CompressionAnnotations: map[string]string{"decompressed": "value"},
			},
			expected: types.BlobInfo{
				Digest:               "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Size:                 513543640,
				URLs:                 nil,
				Annotations:          map[string]string{"test-annotation-2": "two", "decompressed": "value"},
				MediaType:            imgspecv1.MediaTypeImageLayerGzip,
				CompressionOperation: types.Decompress,
				CompressionAlgorithm: nil,
				// CryptoOperation is set to the zero value
			},
		},
		{ // Reuse turning zstd into zstd:chunked
			reused: private.ReusedBlob{
				Digest:                 "sha256:6a5a5368e0c2d3e5909184fa28ddfd56072e7ff3ee9a945876f7eee5896ef5bb",
				Size:                   51354364,
				CompressionOperation:   types.Compress,
				CompressionAlgorithm:   &compression.ZstdChunked,
				CompressionAnnotations: map[string]string{"zstd-toc": "value"},
			},
			expected: types.BlobInfo{
				Digest:               "sha256:6a5a5368e0c2d3e5909184fa28ddfd56072e7ff3ee9a945876f7eee5896ef5bb",
				Size:                 51354364,
				URLs:                 nil,
				Annotations:          map[string]string{"test-annotation-2": "two", "zstd-toc": "value"},
				MediaType:            imgspecv1.MediaTypeImageLayerGzip,
				CompressionOperation: types.Compress,
				CompressionAlgorithm: &compression.ZstdChunked,
				// CryptoOperation is set to the zero value
			},
		},
	} {
		res := updatedBlobInfoFromReuse(srcInfo, c.reused)
		assert.Equal(t, c.expected, res, fmt.Sprintf("%#v", c.reused))
	}
}

func goDiffIDComputationGoroutineWithTimeout(layerStream io.ReadCloser, decompressor compressiontypes.DecompressorFunc) *diffIDResult {
	ch := make(chan diffIDResult)
	go diffIDComputationGoroutine(ch, layerStream, decompressor, digest.Canonical)
	timeout := time.After(time.Second)
	select {
	case res := <-ch:
		return &res
	case <-timeout:
		return nil
	}
}

func TestDiffIDComputationGoroutine(t *testing.T) {
	testCases := []struct {
		name         string
		filename     string
		data         []byte
		decompressor compressiontypes.DecompressorFunc
		algorithm    digest.Algorithm
		expected     string
		expectError  bool
		description  string
	}{
		// SHA256 tests
		{
			name:         "SHA256_Uncompressed",
			filename:     "fixtures/Hello.uncompressed",
			decompressor: nil,
			algorithm:    digest.Canonical,
			expected:     "sha256:185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
			expectError:  false,
			description:  "Should successfully compute SHA256 digest from file",
		},

		// SHA512 tests
		{
			name:         "SHA512_Success",
			data:         []byte("test data for SHA512 digest computation"),
			decompressor: nil,
			algorithm:    digest.SHA512,
			expectError:  false,
			description:  "Should successfully compute SHA512 digest from data",
		},
		{
			name:         "SHA512_LargeData",
			data:         bytes.Repeat([]byte("SHA512 test data with repeated content "), 1000),
			decompressor: nil,
			algorithm:    digest.SHA512,
			expectError:  false,
			description:  "Should handle large data with SHA512",
		},
		{
			name:         "SHA512_WithGzipDecompression",
			filename:     "fixtures/Hello.gz",
			decompressor: compression.GzipDecompressor,
			algorithm:    digest.SHA512,
			expected:     "sha512:3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315",
			expectError:  false,
			description:  "Should handle gzip decompression with SHA512",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var reader io.ReadCloser
			var err error

			if tc.filename != "" {
				reader, err = os.Open(tc.filename)
				require.NoError(t, err, tc.filename)
				defer reader.Close()
			} else {
				reader = io.NopCloser(bytes.NewReader(tc.data))
			}

			// Call diffIDComputationGoroutine directly with the specified algorithm
			resultChan := make(chan diffIDResult, 1)
			go diffIDComputationGoroutine(resultChan, reader, tc.decompressor, tc.algorithm)

			// Wait for result with timeout
			select {
			case result := <-resultChan:
				if tc.expectError {
					assert.Error(t, result.err, tc.description)
				} else {
					assert.NoError(t, result.err, tc.description)
					if tc.expected != "" {
						assert.Equal(t, tc.expected, result.digest.String())
					}
					assert.NotEmpty(t, result.digest, "Digest should not be empty")

					if tc.algorithm == digest.SHA512 {
						assert.True(t, result.digest.Algorithm() == digest.SHA512, "Result should be SHA512")
						assert.True(t, len(result.digest.String()) > 71, "SHA512 should be longer than SHA256")
					}

					t.Logf("%s digest: %s", tc.algorithm, result.digest.String())
				}
			case <-time.After(time.Second):
				t.Fatal("Test timed out waiting for goroutine result")
			}
		})
	}

	// Error reading input test
	t.Run("Error_ReadingInput", func(t *testing.T) {
		reader, writer := io.Pipe()
		err := writer.CloseWithError(errors.New("Expected error reading input in diffIDComputationGoroutine"))
		require.NoError(t, err)
		res := goDiffIDComputationGoroutineWithTimeout(reader, nil)
		require.NotNil(t, res)
		assert.Error(t, res.err)
	})
}

func TestComputeDiffID(t *testing.T) {
	for _, c := range []struct {
		name         string
		filename     string
		decompressor compressiontypes.DecompressorFunc
		algorithm    digest.Algorithm
		result       digest.Digest
	}{
		// SHA256 tests (using digest.Canonical which defaults to SHA256)
		{"SHA256_Uncompressed", "fixtures/Hello.uncompressed", nil, digest.Canonical, "sha256:185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"},
		{"SHA256_Gzip", "fixtures/Hello.gz", nil, digest.Canonical, "sha256:0bd4409dcd76476a263b8f3221b4ce04eb4686dec40bfdcc2e86a7403de13609"},
		{"SHA256_GzipDecompressed", "fixtures/Hello.gz", compression.GzipDecompressor, digest.Canonical, "sha256:185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"},
		{"SHA256_Zstd", "fixtures/Hello.zst", nil, digest.Canonical, "sha256:361a8e0372ad438a0316eb39a290318364c10b60d0a7e55b40aa3eafafc55238"},
		{"SHA256_ZstdDecompressed", "fixtures/Hello.zst", compression.ZstdDecompressor, digest.Canonical, "sha256:185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"},

		// SHA512 tests
		{"SHA512_Uncompressed", "fixtures/Hello.uncompressed", nil, digest.SHA512, "sha512:3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315"},
		{"SHA512_GzipDecompressed", "fixtures/Hello.gz", compression.GzipDecompressor, digest.SHA512, "sha512:3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315"},
		{"SHA512_ZstdDecompressed", "fixtures/Hello.zst", compression.ZstdDecompressor, digest.SHA512, "sha512:3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315"},
		{"SHA512_Gzip", "fixtures/Hello.gz", nil, digest.SHA512, "sha512:8ee9be48dfc6274f65199847cd18ff4711f00329c5063b17cd128ba45ea1b9cea2479db0266cc1f4a3902874fdd7306f9c8a615347c0603b893fc75184fcb627"},
	} {
		t.Run(c.name, func(t *testing.T) {
			stream, err := os.Open(c.filename)
			require.NoError(t, err, c.filename)
			defer stream.Close()

			diffID, err := computeDiffID(stream, c.decompressor, c.algorithm)
			require.NoError(t, err, c.filename)
			assert.Equal(t, c.result, diffID)
		})
	}

	// Error initializing decompression
	_, err := computeDiffID(bytes.NewReader([]byte{}), compression.GzipDecompressor, digest.Canonical)
	assert.Error(t, err)

	// Error reading input
	reader, writer := io.Pipe()
	defer reader.Close()
	err = writer.CloseWithError(errors.New("Expected error reading input in computeDiffID"))
	require.NoError(t, err)
	_, err = computeDiffID(reader, nil, digest.Canonical)
	assert.Error(t, err)
}

// TestComputeDiffIDDigestAgility tests that different digest algorithms produce different results
func TestComputeDiffIDDigestAgility(t *testing.T) {
	testFile := "fixtures/Hello.uncompressed"

	algorithms := []struct {
		name      string
		algorithm digest.Algorithm
	}{
		{"SHA256", digest.SHA256},
		{"SHA512", digest.SHA512},
		{"Canonical", digest.Canonical},
	}

	results := make(map[string]digest.Digest)

	for _, algo := range algorithms {
		t.Run(algo.name, func(t *testing.T) {
			stream, err := os.Open(testFile)
			require.NoError(t, err, testFile)
			defer stream.Close()

			diffID, err := computeDiffID(stream, nil, algo.algorithm)
			require.NoError(t, err, testFile)

			results[algo.name] = diffID
			t.Logf("%s digest: %s", algo.name, diffID)

			// Verify digest is valid and matches expected algorithm
			assert.NoError(t, diffID.Validate(), "Digest should be valid")
			if algo.algorithm == digest.SHA512 {
				assert.True(t, diffID.Algorithm() == digest.SHA512, "Should be SHA512 algorithm")
				assert.Equal(t, 135, len(diffID.String()), "SHA512 digest should be 135 chars (sha512: + 128 hex)")
			} else if algo.algorithm == digest.SHA256 || algo.algorithm == digest.Canonical {
				assert.True(t, diffID.Algorithm() == digest.SHA256, "Should be SHA256 algorithm")
				assert.Equal(t, 71, len(diffID.String()), "SHA256 digest should be 71 chars (sha256: + 64 hex)")
			}
		})
	}

	// Verify that different algorithms produce different results
	assert.NotEqual(t, results["SHA256"], results["SHA512"], "SHA256 and SHA512 should produce different digests")
	assert.Equal(t, results["SHA256"], results["Canonical"], "SHA256 and Canonical should produce same digest (Canonical defaults to SHA256)")
}

// TestDigestAlgorithmConsistencyInCopyLayer tests that the digest algorithm parameter flows correctly
func TestDigestAlgorithmConsistencyInCopyLayer(t *testing.T) {
	// This test verifies that the digest algorithm parameter added to copyLayerFromStream
	// and related functions is properly used and produces consistent results

	testData := []byte("consistency test data for digest algorithms")
	reader := bytes.NewReader(testData)

	algorithms := []digest.Algorithm{
		digest.SHA256,
		digest.SHA512,
	}

	results := make(map[digest.Algorithm]digest.Digest)

	for _, algo := range algorithms {
		t.Run(fmt.Sprintf("Algorithm_%s", algo), func(t *testing.T) {
			// Reset reader
			reader.Seek(0, io.SeekStart)

			// Test computeDiffID directly
			digest1, err := computeDiffID(reader, nil, algo)
			require.NoError(t, err)
			results[algo] = digest1

			// Reset reader and test via diffIDComputationGoroutine
			reader.Seek(0, io.SeekStart)
			readerCloser := io.NopCloser(reader)

			resultChan := make(chan diffIDResult, 1)
			go diffIDComputationGoroutine(resultChan, readerCloser, nil, algo)

			select {
			case result := <-resultChan:
				require.NoError(t, result.err)
				digest2 := result.digest

				// Both methods should produce the same digest
				assert.Equal(t, digest1, digest2, "computeDiffID and diffIDComputationGoroutine should produce identical results")
				assert.Equal(t, algo, digest1.Algorithm(), "Digest should use the specified algorithm")

			case <-time.After(2 * time.Second):
				t.Fatal("Timeout waiting for diffIDComputationGoroutine")
			}
		})
	}

	// Verify different algorithms produce different results
	assert.NotEqual(t, results[digest.SHA256], results[digest.SHA512],
		"Different digest algorithms should produce different results")
}

// TestDigestAlgorithmErrorHandling tests error conditions with different digest algorithms
func TestDigestAlgorithmErrorHandling(t *testing.T) {
	testCases := []struct {
		name        string
		setupError  func() (io.ReadCloser, compressiontypes.DecompressorFunc)
		algorithm   digest.Algorithm
		description string
	}{
		{
			name: "SHA512ReadError",
			setupError: func() (io.ReadCloser, compressiontypes.DecompressorFunc) {
				reader, writer := io.Pipe()
				go func() {
					writer.CloseWithError(errors.New("simulated read error for SHA512 test"))
				}()
				return reader, nil
			},
			algorithm:   digest.SHA512,
			description: "Should handle read errors gracefully with SHA512",
		},
		{
			name: "SHA512DecompressionError",
			setupError: func() (io.ReadCloser, compressiontypes.DecompressorFunc) {
				// Invalid gzip data
				return io.NopCloser(bytes.NewReader([]byte("not gzip data"))), compression.GzipDecompressor
			},
			algorithm:   digest.SHA512,
			description: "Should handle decompression errors gracefully with SHA512",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader, decompressor := tc.setupError()
			defer reader.Close()

			// Test computeDiffID error handling
			_, err := computeDiffID(reader, decompressor, tc.algorithm)
			assert.Error(t, err, tc.description)

			// Reset error condition for goroutine test
			reader, decompressor = tc.setupError()
			defer reader.Close()

			// Test diffIDComputationGoroutine error handling
			resultChan := make(chan diffIDResult, 1)
			go diffIDComputationGoroutine(resultChan, reader, decompressor, tc.algorithm)

			select {
			case result := <-resultChan:
				assert.Error(t, result.err, tc.description)
			case <-time.After(2 * time.Second):
				t.Fatal("Timeout waiting for error result")
			}
		})
	}
}

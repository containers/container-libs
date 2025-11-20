package putblobdigest

import (
	"bytes"
	"io"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/types"
	supportedDigests "go.podman.io/storage/pkg/supported-digests"
)

var testData = []byte("test data")

type testCase struct {
	inputDigest    digest.Digest
	computesDigest bool
	expectedDigest digest.Digest
}

func testDigester(t *testing.T, constructor func(io.Reader, types.BlobInfo) (Digester, io.Reader),
	cases []testCase,
) {
	for _, c := range cases {
		stream := bytes.NewReader(testData)
		digester, newStream := constructor(stream, types.BlobInfo{Digest: c.inputDigest})
		assert.Equal(t, c.computesDigest, newStream != stream, c.inputDigest)
		data, err := io.ReadAll(newStream)
		require.NoError(t, err, c.inputDigest)
		assert.Equal(t, testData, data, c.inputDigest)
		digest := digester.Digest()
		assert.Equal(t, c.expectedDigest, digest, c.inputDigest)
	}
}

// TestDigestAlgorithmConfiguration tests that the digest algorithm configuration works correctly
func TestDigestAlgorithmConfiguration(t *testing.T) {
	// Save original algorithm and restore it after the test
	originalAlgorithm := supportedDigests.TmpDigestForNewObjects()
	defer func() {
		err := supportedDigests.TmpSetDigestForNewObjects(originalAlgorithm)
		require.NoError(t, err)
	}()

	// Test with SHA256 (default)
	err := supportedDigests.TmpSetDigestForNewObjects(digest.SHA256)
	require.NoError(t, err)

	stream := bytes.NewReader(testData)
	digester, newStream := DigestIfConfiguredUnknown(stream, types.BlobInfo{Digest: digest.Digest("")})
	_, err = io.ReadAll(newStream)
	require.NoError(t, err)

	// The digest should be computed using SHA256
	expectedSHA256 := digest.SHA256.FromBytes(testData)
	assert.Equal(t, expectedSHA256, digester.Digest())

	// Test with SHA512
	err = supportedDigests.TmpSetDigestForNewObjects(digest.SHA512)
	require.NoError(t, err)

	stream = bytes.NewReader(testData)
	digester, newStream = DigestIfConfiguredUnknown(stream, types.BlobInfo{Digest: digest.Digest("")})
	_, err = io.ReadAll(newStream)
	require.NoError(t, err)

	// The digest should be computed using SHA512
	expectedSHA512 := digest.SHA512.FromBytes(testData)
	assert.Equal(t, expectedSHA512, digester.Digest())
}

func TestDigestIfUnknown(t *testing.T) {
	testDigester(t, DigestIfUnknown, []testCase{
		{
			inputDigest:    digest.Digest("sha256:uninspected-value"),
			computesDigest: false,
			expectedDigest: digest.Digest("sha256:uninspected-value"),
		},
		{
			inputDigest:    digest.Digest("sha512:uninspected-value"),
			computesDigest: false,
			expectedDigest: digest.Digest("sha512:uninspected-value"),
		},
		{
			inputDigest:    digest.Digest(""),
			computesDigest: true,
			expectedDigest: digest.SHA256.FromBytes(testData),
		},
		{
			inputDigest:    digest.Digest("unknown-algorithm:uninspected-value"),
			computesDigest: false,
			expectedDigest: digest.Digest("unknown-algorithm:uninspected-value"),
		},
		{
			inputDigest:    "",
			computesDigest: true,
			expectedDigest: digest.Canonical.FromBytes(testData),
		},
	})
}

func TestDigestIfConfiguredUnknown(t *testing.T) {
	// Save original algorithm and restore it after the test
	originalAlgorithm := supportedDigests.TmpDigestForNewObjects()
	defer func() {
		err := supportedDigests.TmpSetDigestForNewObjects(originalAlgorithm)
		require.NoError(t, err)
	}()

	// Test with SHA256 (default) - this exercises the default behavior
	err := supportedDigests.TmpSetDigestForNewObjects(digest.SHA256)
	require.NoError(t, err)

	testDigester(t, DigestIfConfiguredUnknown, []testCase{
		{
			inputDigest:    digest.Digest("sha256:uninspected-value"),
			computesDigest: false,
			expectedDigest: digest.Digest("sha256:uninspected-value"),
		},
		{
			inputDigest:    digest.Digest("sha512:uninspected-value"),
			computesDigest: true,
			expectedDigest: digest.SHA256.FromBytes(testData),
		},
		{
			inputDigest:    digest.Digest("unknown-algorithm:uninspected-value"),
			computesDigest: true,
			expectedDigest: digest.SHA256.FromBytes(testData),
		},
		{
			inputDigest:    "",
			computesDigest: true,
			expectedDigest: digest.SHA256.FromBytes(testData),
		},
	})

	// Test with SHA512 - this exercises the newly added SHA512 functionality
	err = supportedDigests.TmpSetDigestForNewObjects(digest.SHA512)
	require.NoError(t, err)

	testDigester(t, DigestIfConfiguredUnknown, []testCase{
		{
			inputDigest:    digest.Digest("sha256:uninspected-value"),
			computesDigest: true,
			expectedDigest: digest.SHA512.FromBytes(testData),
		},
		{
			inputDigest:    digest.Digest("sha512:uninspected-value"),
			computesDigest: false,
			expectedDigest: digest.Digest("sha512:uninspected-value"),
		},
		{
			inputDigest:    digest.Digest("unknown-algorithm:uninspected-value"),
			computesDigest: true,
			expectedDigest: digest.SHA512.FromBytes(testData),
		},
		{
			inputDigest:    "",
			computesDigest: true,
			expectedDigest: digest.SHA512.FromBytes(testData),
		},
	})
}

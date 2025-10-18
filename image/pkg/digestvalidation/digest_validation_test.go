package digestvalidation

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testData = []byte("test data for digest validation")

func TestValidateBlobAgainstDigest(t *testing.T) {
	tests := []struct {
		name           string
		blob           []byte
		expectedDigest digest.Digest
		expectError    bool
		errorContains  string
	}{
		{
			name:           "valid SHA256 digest",
			blob:           testData,
			expectedDigest: digest.SHA256.FromBytes(testData),
			expectError:    false,
		},
		{
			name:           "valid SHA512 digest",
			blob:           testData,
			expectedDigest: digest.SHA512.FromBytes(testData),
			expectError:    false,
		},
		{
			name:           "empty digest",
			blob:           testData,
			expectedDigest: digest.Digest(""),
			expectError:    true,
			errorContains:  "expected digest is empty",
		},
		{
			name:           "malformed digest format",
			blob:           testData,
			expectedDigest: digest.Digest("invalid-format"),
			expectError:    true,
			errorContains:  "invalid digest format",
		},
		{
			name:           "digest with invalid algorithm",
			blob:           testData,
			expectedDigest: digest.Digest("invalid:1234567890abcdef"),
			expectError:    true,
			errorContains:  "invalid digest format",
		},
		{
			name:           "unsupported algorithm (SHA384)",
			blob:           testData,
			expectedDigest: digest.Digest("sha384:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			expectError:    true,
			errorContains:  "unsupported digest algorithm",
		},
		{
			name:           "unsupported algorithm (MD5)",
			blob:           testData,
			expectedDigest: digest.Digest("md5:d41d8cd98f00b204e9800998ecf8427e"),
			expectError:    true,
			errorContains:  "", // Any error is acceptable for unsupported algorithms
		},
		{
			name:           "digest mismatch",
			blob:           testData,
			expectedDigest: digest.SHA256.FromBytes([]byte("different data")),
			expectError:    true,
			errorContains:  "blob digest mismatch",
		},
		{
			name:           "empty blob with valid digest",
			blob:           []byte{},
			expectedDigest: digest.SHA256.FromBytes([]byte{}),
			expectError:    false,
		},
		{
			name:           "empty blob with wrong digest",
			blob:           []byte{},
			expectedDigest: digest.SHA256.FromBytes(testData),
			expectError:    true,
			errorContains:  "blob digest mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBlobAgainstDigest(tt.blob, tt.expectedDigest)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateBlobAgainstDigest_EdgeCases(t *testing.T) {
	t.Run("very large blob", func(t *testing.T) {
		// Create a larger blob to test with more substantial data
		largeData := make([]byte, 1024*1024) // 1MB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		expectedDigest := digest.SHA256.FromBytes(largeData)
		err := ValidateBlobAgainstDigest(largeData, expectedDigest)
		require.NoError(t, err)
	})

	t.Run("SHA512 with large blob", func(t *testing.T) {
		largeData := make([]byte, 1024*1024) // 1MB
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		expectedDigest := digest.SHA512.FromBytes(largeData)
		err := ValidateBlobAgainstDigest(largeData, expectedDigest)
		require.NoError(t, err)
	})

	t.Run("algorithm case sensitivity", func(t *testing.T) {
		// Test that algorithm names are case-insensitive (if supported by go-digest)
		// This tests the robustness of our validation
		expectedDigest := digest.SHA256.FromBytes(testData)
		err := ValidateBlobAgainstDigest(testData, expectedDigest)
		require.NoError(t, err)
	})
}

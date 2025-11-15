package image

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBlobAgainstDigest(t *testing.T) {
	testBlob := []byte("test data")

	tests := []struct {
		name           string
		blob           []byte
		expectedDigest digest.Digest
		expectError    bool
		errorContains  string
	}{
		{
			name:           "empty digest",
			blob:           testBlob,
			expectedDigest: "",
			expectError:    true,
			errorContains:  "expected digest is empty",
		},
		{
			name:           "invalid digest format - no algorithm",
			blob:           testBlob,
			expectedDigest: "invalidsyntax",
			expectError:    true,
			errorContains:  "invalid digest format",
		},
		{
			name:           "invalid digest format - sha256 prefix w/ malformed hex",
			blob:           testBlob,
			expectedDigest: "sha256:notahexstring!@#",
			expectError:    true,
			errorContains:  "invalid digest format",
		},
		{
			name:           "invalid digest format - sha512 prefix w/ malformed hex",
			blob:           testBlob,
			expectedDigest: "sha512:notahexstring!@#",
			expectError:    true,
			errorContains:  "invalid digest format",
		},
		{
			name:           "invalid digest format - unknown algorithm",
			blob:           testBlob,
			expectedDigest: "unknown-algo:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			expectError:    true,
			errorContains:  "invalid digest format",
		},
		{
			name:           "digest mismatch",
			blob:           testBlob,
			expectedDigest: digest.SHA256.FromBytes([]byte("different data")),
			expectError:    true,
			errorContains:  "blob digest",
		},
		{
			name:           "empty blob with matching digest",
			blob:           []byte{},
			expectedDigest: digest.SHA256.FromBytes([]byte{}),
			expectError:    false,
		},
		{
			name:           "unavailable algorithm - blake2b",
			blob:           testBlob,
			expectedDigest: "blake2b:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			expectError:    true,
			errorContains:  "invalid digest format",
		},
		{
			name:           "sha256 digest success",
			blob:           testBlob,
			expectedDigest: digest.SHA256.FromBytes(testBlob),
			expectError:    false,
		},
		{
			name:           "sha512 digest success",
			blob:           testBlob,
			expectedDigest: digest.SHA512.FromBytes(testBlob),
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBlobAgainstDigest(tt.blob, tt.expectedDigest)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

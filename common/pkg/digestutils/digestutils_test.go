//go:build !remote

package digestutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsDigestReference tests the IsDigestReference function to ensure
// it properly detects digest references while avoiding conflicts with repository names.
func TestIsDigestReference(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
		desc     string
	}{
		// Valid digest formats
		{
			name:     "sha256_digest",
			input:    "sha256:916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9",
			expected: true,
			desc:     "Valid SHA256 digest should be detected",
		},
		{
			name:     "sha512_digest",
			input:    "sha512:0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d",
			expected: true,
			desc:     "Valid SHA512 digest should be detected",
		},
		{
			name:     "sha256_invalid_hash",
			input:    "sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
			expected: true,
			desc:     "SHA256 with invalid hash should still be detected as digest format",
		},

		// Legacy 64-character hex format (backward compatibility)
		{
			name:     "legacy_sha256_hex",
			input:    "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
			expected: true,
			desc:     "Legacy 64-character hex format should be detected",
		},

		// Repository names that should NOT be detected as digests
		{
			name:     "sha256_repo_name",
			input:    "sha256",
			expected: false,
			desc:     "Repository name 'sha256' should NOT be detected as digest",
		},
		{
			name:     "sha512_repo_name",
			input:    "sha512",
			expected: false,
			desc:     "Repository name 'sha512' should NOT be detected as digest",
		},
		{
			name:     "sha256_with_tag",
			input:    "sha256:latest",
			expected: false,
			desc:     "Repository 'sha256' with tag should NOT be detected as digest",
		},
		{
			name:     "sha512_with_tag",
			input:    "sha512:latest",
			expected: false,
			desc:     "Repository 'sha512' with tag should NOT be detected as digest",
		},
		{
			name:     "sha256_with_domain",
			input:    "docker.io/sha256:latest",
			expected: false,
			desc:     "Repository 'docker.io/sha256' should NOT be detected as digest",
		},
		{
			name:     "sha512_with_domain",
			input:    "quay.io/sha512:latest",
			expected: false,
			desc:     "Repository 'quay.io/sha512' should NOT be detected as digest",
		},

		// Invalid digest formats
		{
			name:     "invalid_digest_format",
			input:    "sha256:invalid",
			expected: false,
			desc:     "Invalid digest format should NOT be detected",
		},
		{
			name:     "too_short_hex",
			input:    "abcd1234",
			expected: false,
			desc:     "Too short hex string should NOT be detected",
		},
		{
			name:     "too_long_hex",
			input:    "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expected: false,
			desc:     "Too long hex string should NOT be detected",
		},
		{
			name:     "non_hex_characters",
			input:    "ghij567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expected: false,
			desc:     "Non-hex characters should NOT be detected",
		},

		// Edge cases
		{
			name:     "empty_string",
			input:    "",
			expected: false,
			desc:     "Empty string should NOT be detected as digest",
		},
		{
			name:     "with_slash",
			input:    "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab/",
			expected: false,
			desc:     "Hex with slash should NOT be detected (not legacy format)",
		},
		{
			name:     "with_dot",
			input:    "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab.",
			expected: false,
			desc:     "Hex with dot should NOT be detected (not legacy format)",
		},
		{
			name:     "with_colon",
			input:    "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab:",
			expected: false,
			desc:     "Hex with colon should NOT be detected (not legacy format)",
		},
		{
			name:     "with_at",
			input:    "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab@",
			expected: false,
			desc:     "Hex with @ should NOT be detected (not legacy format)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsDigestReference(test.input)
			assert.Equal(t, test.expected, result,
				"Test: %s\nInput: %q\nExpected: %v, Got: %v\nDescription: %s",
				test.name, test.input, test.expected, result, test.desc)
		})
	}
}

// TestExtractAlgorithmFromDigest tests the ExtractAlgorithmFromDigest function to ensure
// it properly extracts algorithm and hash from digest strings with @ prefix.
func TestExtractAlgorithmFromDigest(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedAlg  string
		expectedHash string
		desc         string
	}{
		// Valid digest formats with @ prefix (using real digest values)
		{
			name:         "sha256_with_at_prefix",
			input:        "@sha256:916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9",
			expectedAlg:  "sha256",
			expectedHash: "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9",
			desc:         "SHA256 digest with @ prefix should extract algorithm and hash",
		},
		{
			name:         "sha512_with_at_prefix",
			input:        "@sha512:0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d",
			expectedAlg:  "sha512",
			expectedHash: "0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d",
			desc:         "SHA512 digest with @ prefix should extract algorithm and hash",
		},

		// Invalid formats (should return empty strings)
		{
			name:         "missing_at_prefix",
			input:        "sha256:abc123",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Digest without @ prefix should return empty strings",
		},
		{
			name:         "missing_colon",
			input:        "@sha256",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Digest without colon should return empty strings",
		},
		{
			name:         "empty_string",
			input:        "",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Empty string should return empty strings",
		},
		{
			name:         "only_at_prefix",
			input:        "@",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Only @ prefix should return empty strings",
		},
		{
			name:         "at_with_colon_only",
			input:        "@:",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "@: should return empty strings",
		},

		// Edge cases (should fail validation)
		{
			name:         "multiple_colons",
			input:        "@sha256:abc:def:ghi",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Multiple colons should fail validation",
		},
		{
			name:         "empty_algorithm",
			input:        "@:abc123",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Empty algorithm should fail validation",
		},
		{
			name:         "empty_hash",
			input:        "@sha256:",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Empty hash should cause validation failure",
		},
		{
			name:         "whitespace_in_algorithm",
			input:        "@ sha256:abc123",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Whitespace in algorithm should cause validation failure",
		},
		{
			name:         "whitespace_in_hash",
			input:        "@sha256: abc123 ",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Whitespace in hash should cause validation failure",
		},

		// Invalid digest formats (should return empty strings due to validation)
		{
			name:         "invalid_hash_format",
			input:        "@sha256:invalid",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Invalid hash format should return empty strings",
		},
		{
			name:         "invalid_algorithm",
			input:        "@invalid:abc123",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Invalid algorithm should return empty strings",
		},
		{
			name:         "wrong_hash_length",
			input:        "@sha256:abc",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Wrong hash length should return empty strings",
		},
		{
			name:         "non_hex_hash",
			input:        "@sha256:ghijklmnop",
			expectedAlg:  "",
			expectedHash: "",
			desc:         "Non-hex hash should return empty strings",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			algorithm, hash := ExtractAlgorithmFromDigest(test.input)
			assert.Equal(t, test.expectedAlg, algorithm,
				"Test: %s\nInput: %q\nExpected algorithm: %q, Got: %q\nDescription: %s",
				test.name, test.input, test.expectedAlg, algorithm, test.desc)
			assert.Equal(t, test.expectedHash, hash,
				"Test: %s\nInput: %q\nExpected hash: %q, Got: %q\nDescription: %s",
				test.name, test.input, test.expectedHash, hash, test.desc)
		})
	}
}

// TestHasDigestPrefix tests the HasDigestPrefix function to ensure
// it properly detects digest prefixes for all supported algorithms.
func TestHasDigestPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
		desc     string
	}{
		// Valid digest prefixes
		{
			name:     "sha256_prefix",
			input:    "sha256:abc123",
			expected: true,
			desc:     "SHA256 prefix should be detected",
		},
		{
			name:     "sha512_prefix",
			input:    "sha512:def456",
			expected: true,
			desc:     "SHA512 prefix should be detected",
		},

		// Invalid cases
		{
			name:     "no_prefix",
			input:    "image:latest",
			expected: false,
			desc:     "Image tag should not be detected as digest",
		},
		{
			name:     "registry_repo",
			input:    "registry.io/repo:tag",
			expected: false,
			desc:     "Registry repository should not be detected as digest",
		},
		{
			name:     "empty_string",
			input:    "",
			expected: false,
			desc:     "Empty string should not be detected as digest",
		},
		{
			name:     "partial_prefix",
			input:    "sha256",
			expected: false,
			desc:     "Partial prefix without colon should not be detected",
		},
		{
			name:     "unsupported_algorithm",
			input:    "md5:abc123",
			expected: false,
			desc:     "Unsupported algorithm should not be detected",
		},
		{
			name:     "sha3_256_prefix",
			input:    "sha3-256:ghi789",
			expected: false,
			desc:     "SHA3-256 prefix should not be detected (not supported)",
		},
		{
			name:     "sha3_512_prefix",
			input:    "sha3-512:jkl012",
			expected: false,
			desc:     "SHA3-512 prefix should not be detected (not supported)",
		},
		{
			name:     "blake2b_256_prefix",
			input:    "blake2b-256:mno345",
			expected: false,
			desc:     "Blake2b-256 prefix should not be detected (not supported)",
		},
		{
			name:     "blake2b_512_prefix",
			input:    "blake2b-512:pqr678",
			expected: false,
			desc:     "Blake2b-512 prefix should not be detected (not supported)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := HasDigestPrefix(test.input)
			assert.Equal(t, test.expected, result,
				"Test: %s\nInput: %q\nExpected: %v, Got: %v\nDescription: %s",
				test.name, test.input, test.expected, result, test.desc)
		})
	}
}

// TestGetDigestPrefix tests the GetDigestPrefix function to ensure
// it properly extracts digest algorithm prefixes.
func TestGetDigestPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		desc     string
	}{
		// Valid digest prefixes
		{
			name:     "sha256_prefix",
			input:    "sha256:abc123",
			expected: "sha256:",
			desc:     "SHA256 prefix should be extracted",
		},
		{
			name:     "sha512_prefix",
			input:    "sha512:def456",
			expected: "sha512:",
			desc:     "SHA512 prefix should be extracted",
		},

		// Invalid cases
		{
			name:     "no_prefix",
			input:    "image:latest",
			expected: "",
			desc:     "Image tag should return empty prefix",
		},
		{
			name:     "registry_repo",
			input:    "registry.io/repo:tag",
			expected: "",
			desc:     "Registry repository should return empty prefix",
		},
		{
			name:     "empty_string",
			input:    "",
			expected: "",
			desc:     "Empty string should return empty prefix",
		},
		{
			name:     "partial_prefix",
			input:    "sha256",
			expected: "",
			desc:     "Partial prefix should return empty prefix",
		},
		{
			name:     "unsupported_algorithm",
			input:    "md5:abc123",
			expected: "",
			desc:     "Unsupported algorithm should return empty prefix",
		},
		{
			name:     "sha3_256_prefix",
			input:    "sha3-256:ghi789",
			expected: "",
			desc:     "SHA3-256 prefix should return empty (not supported)",
		},
		{
			name:     "sha3_512_prefix",
			input:    "sha3-512:jkl012",
			expected: "",
			desc:     "SHA3-512 prefix should return empty (not supported)",
		},
		{
			name:     "blake2b_256_prefix",
			input:    "blake2b-256:mno345",
			expected: "",
			desc:     "Blake2b-256 prefix should return empty (not supported)",
		},
		{
			name:     "blake2b_512_prefix",
			input:    "blake2b-512:pqr678",
			expected: "",
			desc:     "Blake2b-512 prefix should return empty (not supported)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GetDigestPrefix(test.input)
			assert.Equal(t, test.expected, result,
				"Test: %s\nInput: %q\nExpected: %q, Got: %q\nDescription: %s",
				test.name, test.input, test.expected, result, test.desc)
		})
	}
}

// TestTrimDigestPrefix tests the TrimDigestPrefix function to ensure
// it properly removes digest algorithm prefixes.
func TestTrimDigestPrefix(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedResult string
		expectedFound  bool
		desc           string
	}{
		// Valid digest prefixes
		{
			name:           "sha256_prefix",
			input:          "sha256:abc123",
			expectedResult: "abc123",
			expectedFound:  true,
			desc:           "SHA256 prefix should be removed",
		},
		{
			name:           "sha512_prefix",
			input:          "sha512:def456",
			expectedResult: "def456",
			expectedFound:  true,
			desc:           "SHA512 prefix should be removed",
		},

		// Invalid cases
		{
			name:           "no_prefix",
			input:          "image:latest",
			expectedResult: "image:latest",
			expectedFound:  false,
			desc:           "Image tag should not be modified",
		},
		{
			name:           "registry_repo",
			input:          "registry.io/repo:tag",
			expectedResult: "registry.io/repo:tag",
			expectedFound:  false,
			desc:           "Registry repository should not be modified",
		},
		{
			name:           "empty_string",
			input:          "",
			expectedResult: "",
			expectedFound:  false,
			desc:           "Empty string should not be modified",
		},
		{
			name:           "partial_prefix",
			input:          "sha256",
			expectedResult: "sha256",
			expectedFound:  false,
			desc:           "Partial prefix should not be modified",
		},
		{
			name:           "unsupported_algorithm",
			input:          "md5:abc123",
			expectedResult: "md5:abc123",
			expectedFound:  false,
			desc:           "Unsupported algorithm should not be modified",
		},
		{
			name:           "sha3_256_prefix",
			input:          "sha3-256:ghi789",
			expectedResult: "sha3-256:ghi789",
			expectedFound:  false,
			desc:           "SHA3-256 prefix should not be modified (not supported)",
		},
		{
			name:           "sha3_512_prefix",
			input:          "sha3-512:jkl012",
			expectedResult: "sha3-512:jkl012",
			expectedFound:  false,
			desc:           "SHA3-512 prefix should not be modified (not supported)",
		},
		{
			name:           "blake2b_256_prefix",
			input:          "blake2b-256:mno345",
			expectedResult: "blake2b-256:mno345",
			expectedFound:  false,
			desc:           "Blake2b-256 prefix should not be modified (not supported)",
		},
		{
			name:           "blake2b_512_prefix",
			input:          "blake2b-512:pqr678",
			expectedResult: "blake2b-512:pqr678",
			expectedFound:  false,
			desc:           "Blake2b-512 prefix should not be modified (not supported)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, found := TrimDigestPrefix(test.input)
			assert.Equal(t, test.expectedResult, result,
				"Test: %s\nInput: %q\nExpected result: %q, Got: %q\nDescription: %s",
				test.name, test.input, test.expectedResult, result, test.desc)
			assert.Equal(t, test.expectedFound, found,
				"Test: %s\nInput: %q\nExpected found: %v, Got: %v\nDescription: %s",
				test.name, test.input, test.expectedFound, found, test.desc)
		})
	}
}

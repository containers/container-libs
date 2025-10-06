//go:build !remote

package digestutils

import (
	"strings"

	"github.com/opencontainers/go-digest"
)

// IsDigestReference determines if the given name is a digest-based reference.
// This function properly detects digests using the go-digest library instead of
// hardcoded string prefixes, avoiding conflicts with repository names like "sha256" or "sha512".
//
// The function supports:
// - Standard digest formats (algorithm:hash) like "sha256:abc123..." or "sha512:def456..."
// - Legacy 64-character hex format (SHA256 without algorithm prefix) for backward compatibility
//
// Examples:
//   - "sha256:916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9" → true
//   - "sha512:0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d" → true
//   - "abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab" → true (legacy)
//   - "sha256" → false (repository name)
//   - "sha512:latest" → false (repository with tag)
//   - "docker.io/sha256:latest" → false (repository with domain)
func IsDigestReference(name string) bool {
	// First check if it's a valid digest format (algorithm:hash)
	if _, err := digest.Parse(name); err == nil {
		return true
	}

	// Also check for the legacy 64-character hex format (SHA256 without algorithm prefix)
	// This maintains backward compatibility for existing deployments
	if len(name) == 64 && !strings.ContainsAny(name, "/.:@") {
		// Verify it's actually hex
		for _, c := range name {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
		return true
	}

	return false
}

// ExtractAlgorithmFromDigest extracts the algorithm and hash from a digest string.
// It expects input like "@sha256:abc123" or "@sha512:def456".
// Returns (algorithm, hash) if successful, or ("", "") if parsing fails.
//
// This function validates that the extracted algorithm and hash form a valid digest.
// It is useful for preserving the algorithm that was determined by functions like getImageID,
// rather than overriding it with a globally configured algorithm.
//
// Examples:
//   - "@sha256:abc123" → ("sha256", "abc123") (if valid)
//   - "@sha512:def456" → ("sha512", "def456") (if valid)
//   - "sha256:abc123" → ("", "") (missing @ prefix)
//   - "@invalid" → ("", "") (missing colon)
//   - "@sha256:invalid" → ("", "") (invalid hash format)
func ExtractAlgorithmFromDigest(digestStr string) (string, string) {
	if !strings.HasPrefix(digestStr, "@") {
		return "", ""
	}

	// Remove the "@" prefix
	digestStr = digestStr[1:]

	// Split on the first ":" to get algorithm:hash
	parts := strings.SplitN(digestStr, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}

	algorithm, hash := parts[0], parts[1]

	// Validate that the algorithm and hash form a valid digest
	// This ensures we only return valid digest components
	if _, err := digest.Parse(algorithm + ":" + hash); err != nil {
		return "", ""
	}

	return algorithm, hash
}

// HasDigestPrefix checks if a string starts with any supported digest algorithm prefix.
// This is more scalable than hardcoding multiple HasPrefix checks for individual algorithms.
//
// Examples:
//   - "sha256:abc123" → true
//   - "sha512:def456" → true
//   - "image:latest" → false
//   - "registry.io/repo" → false
func HasDigestPrefix(s string) bool {
	// Check if the string starts with any supported digest algorithm
	// This is more efficient than checking each algorithm individually
	for _, prefix := range []string{"sha256:", "sha512:"} {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// GetDigestPrefix returns the digest algorithm prefix if the string starts with one.
// Returns the prefix (including colon) if found, empty string otherwise.
//
// Examples:
//   - "sha256:abc123" → "sha256:"
//   - "sha512:def456" → "sha512:"
//   - "image:latest" → ""
func GetDigestPrefix(s string) string {
	prefixes := []string{"sha256:", "sha512:"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return prefix
		}
	}
	return ""
}

// TrimDigestPrefix removes the digest algorithm prefix from a string if present.
// Returns the string without the prefix and a boolean indicating if a prefix was found.
//
// Examples:
//   - "sha256:abc123" → ("abc123", true)
//   - "sha512:def456" → ("def456", true)
//   - "image:latest" → ("image:latest", false)
func TrimDigestPrefix(s string) (string, bool) {
	if prefix := GetDigestPrefix(s); prefix != "" {
		return strings.TrimPrefix(s, prefix), true
	}
	return s, false
}

package docker

import (
	"testing"

	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// isSigstoreReferrer Tests
// =============================================================================

func TestIsSigstoreReferrer(t *testing.T) {
	t.Run("sigstore bundle artifact type", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType:    imgspecv1.MediaTypeImageManifest,
			ArtifactType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
			Digest:       "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:         1234,
		}
		assert.True(t, isSigstoreReferrer(desc))
	})

	t.Run("sigstore verificationmaterial artifact type", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType:    imgspecv1.MediaTypeImageManifest,
			ArtifactType: "application/vnd.dev.sigstore.verificationmaterial+json;version=0.3",
			Digest:       "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:         1234,
		}
		assert.True(t, isSigstoreReferrer(desc))
	})

	t.Run("cosign simplesigning artifact type", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType:    imgspecv1.MediaTypeImageManifest,
			ArtifactType: "application/vnd.dev.cosign.simplesigning.v1+json",
			Digest:       "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:         1234,
		}
		assert.True(t, isSigstoreReferrer(desc))
	})

	t.Run("sigstore media type fallback", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.3",
			Digest:    "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:      1234,
		}
		assert.True(t, isSigstoreReferrer(desc))
	})

	t.Run("cosign media type fallback", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType: "application/vnd.dev.cosign.simplesigning.v1+json",
			Digest:    "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:      1234,
		}
		assert.True(t, isSigstoreReferrer(desc))
	})

	t.Run("empty artifact type placeholder", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType:    imgspecv1.MediaTypeImageManifest,
			ArtifactType: "application/vnd.oci.empty.v1+json",
			Digest:       "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:         1234,
		}
		assert.True(t, isSigstoreReferrer(desc))
	})

	t.Run("unrelated artifact type rejected", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType:    imgspecv1.MediaTypeImageManifest,
			ArtifactType: "application/vnd.example.artifact+json",
			Digest:       "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:         1234,
		}
		assert.False(t, isSigstoreReferrer(desc))
	})

	t.Run("plain OCI manifest without artifact type rejected", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType: imgspecv1.MediaTypeImageManifest,
			Digest:    "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:      1234,
		}
		assert.False(t, isSigstoreReferrer(desc))
	})

	t.Run("SBOM artifact type rejected", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType:    imgspecv1.MediaTypeImageManifest,
			ArtifactType: "application/spdx+json",
			Digest:       "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:         1234,
		}
		assert.False(t, isSigstoreReferrer(desc))
	})

	t.Run("attestation artifact type", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType:    imgspecv1.MediaTypeImageManifest,
			ArtifactType: "application/vnd.dev.sigstore.attestation+json",
			Digest:       "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:         1234,
		}
		assert.True(t, isSigstoreReferrer(desc))
	})

	t.Run("cosign attestation artifact type", func(t *testing.T) {
		desc := imgspecv1.Descriptor{
			MediaType:    imgspecv1.MediaTypeImageManifest,
			ArtifactType: "application/vnd.dev.cosign.attestation.v1+json",
			Digest:       "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Size:         1234,
		}
		assert.True(t, isSigstoreReferrer(desc))
	})
}

// =============================================================================
// Referrers Tag Conversion Tests
// =============================================================================

func TestReferrersTagConversion(t *testing.T) {
	// Test the tag format conversion used in getReferrersFromTag
	// Digest format: sha256:abc123 -> Tag format: sha256-abc123

	testCases := []struct {
		digest      string
		expectedTag string
	}{
		{
			digest:      "sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00",
			expectedTag: "sha256-634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00",
		},
		{
			digest:      "sha512:abcdef1234567890",
			expectedTag: "sha512-abcdef1234567890",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.digest, func(t *testing.T) {
			// This mimics the conversion in getReferrersFromTag
			tag := replaceColonWithDash(tc.digest)
			assert.Equal(t, tc.expectedTag, tag)
		})
	}
}

// replaceColonWithDash is a helper that mimics the tag conversion in getReferrersFromTag
func replaceColonWithDash(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			result[i] = '-'
		} else {
			result[i] = s[i]
		}
	}
	return string(result)
}

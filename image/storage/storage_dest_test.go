package storage

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	supporteddigests "go.podman.io/storage/pkg/supported-digests"
)

func TestLayerID(t *testing.T) {
	blobDigestSHA256, err := digest.Parse("sha256:0000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	blobDigestSHA512, err := digest.Parse("sha512:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)

	for _, c := range []struct {
		algorithm       digest.Algorithm
		blobDigest      digest.Digest
		parentID        string
		identifiedByTOC bool
		diffID          string
		tocDigest       string
		expected        string
	}{
		{
			algorithm:       digest.SHA256,
			blobDigest:      blobDigestSHA256,
			parentID:        "",
			identifiedByTOC: false,
			diffID:          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			tocDigest:       "",
			expected:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			algorithm:       digest.SHA256,
			blobDigest:      blobDigestSHA256,
			parentID:        "",
			identifiedByTOC: false,
			diffID:          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expected:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			tocDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		{
			algorithm:       digest.SHA256,
			blobDigest:      blobDigestSHA256,
			parentID:        "",
			identifiedByTOC: true,
			diffID:          "",
			tocDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			expected:        "sha256:07f60ddaf18a3d1fa18a71bf40f0b9889b473e26555d6fffdfbd72ba6a59469e",
		},
		{
			algorithm:       digest.SHA256,
			blobDigest:      blobDigestSHA256,
			parentID:        "",
			identifiedByTOC: true,
			diffID:          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			tocDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			expected:        "sha256:07f60ddaf18a3d1fa18a71bf40f0b9889b473e26555d6fffdfbd72ba6a59469e",
		},
		{
			algorithm:       digest.SHA256,
			blobDigest:      blobDigestSHA256,
			parentID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			identifiedByTOC: false,
			diffID:          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			tocDigest:       "",
			expected:        "sha256:76f79efda453922cda1cecb6ec9e7cf9d86ea968c6dd199d4030dd00078a1686",
		},
		{
			algorithm:       digest.SHA256,
			blobDigest:      blobDigestSHA256,
			parentID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			identifiedByTOC: false,
			diffID:          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			tocDigest:       "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			expected:        "sha256:76f79efda453922cda1cecb6ec9e7cf9d86ea968c6dd199d4030dd00078a1686",
		},
		{
			algorithm:       digest.SHA256,
			blobDigest:      blobDigestSHA256,
			parentID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			identifiedByTOC: true,
			diffID:          "",
			tocDigest:       "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			expected:        "sha256:468becc3d25ee862f81fd728d229a2b2487cfc9b3e6cf3a4d0af8c3fdde0e7a9",
		},
		{
			algorithm:       digest.SHA256,
			blobDigest:      blobDigestSHA256,
			parentID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			identifiedByTOC: true,
			diffID:          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			tocDigest:       "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			expected:        "sha256:468becc3d25ee862f81fd728d229a2b2487cfc9b3e6cf3a4d0af8c3fdde0e7a9",
		},
		{
			algorithm:       digest.SHA512,
			blobDigest:      blobDigestSHA512,
			parentID:        "",
			identifiedByTOC: false,
			diffID:          "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			tocDigest:       "",
			expected:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			algorithm:       digest.SHA512,
			blobDigest:      blobDigestSHA512,
			parentID:        "",
			identifiedByTOC: false,
			diffID:          "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			tocDigest:       "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			expected:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			algorithm:       digest.SHA512,
			blobDigest:      blobDigestSHA512,
			parentID:        "",
			identifiedByTOC: true,
			diffID:          "",
			tocDigest:       "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			expected:        "sha512:129fa63234ab81f43f298346bb7159cc1c8fab6d8ae93f3438f8637f5079ea6dec6ea4740eb6bdbcae3ad1eb00af76011341b2f19fe590daf6f64f06e1302f52",
		},
		{
			algorithm:       digest.SHA512,
			blobDigest:      blobDigestSHA512,
			parentID:        "",
			identifiedByTOC: true,
			diffID:          "sha512:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			tocDigest:       "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			expected:        "sha512:129fa63234ab81f43f298346bb7159cc1c8fab6d8ae93f3438f8637f5079ea6dec6ea4740eb6bdbcae3ad1eb00af76011341b2f19fe590daf6f64f06e1302f52",
		},
		{
			algorithm:       digest.SHA512,
			blobDigest:      blobDigestSHA512,
			parentID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			identifiedByTOC: false,
			diffID:          "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			tocDigest:       "",
			expected:        "sha512:391623fa853a82d2795e8648f06b7c0eb880e345138dd6b9429132d9aa329ff1e6f7b76a3295b8b34d8682090056a798901b9b700e4059b1011d32b68a7bca21",
		},
		{
			algorithm:       digest.SHA512,
			blobDigest:      blobDigestSHA512,
			parentID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			identifiedByTOC: false,
			diffID:          "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			tocDigest:       "sha512:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			expected:        "sha512:391623fa853a82d2795e8648f06b7c0eb880e345138dd6b9429132d9aa329ff1e6f7b76a3295b8b34d8682090056a798901b9b700e4059b1011d32b68a7bca21",
		},
		{
			algorithm:       digest.SHA512,
			blobDigest:      blobDigestSHA512,
			parentID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			identifiedByTOC: true,
			diffID:          "",
			tocDigest:       "sha512:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			expected:        "sha512:0263be0fd3b851ffe02c877574d1d2b19625e36888e63eec2682de2210b6bbaea262e04085843eda16b7014fd59db6aafa0628c2a02443111ae568ea545b112e",
		},
		{
			algorithm:       digest.SHA512,
			blobDigest:      blobDigestSHA512,
			parentID:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			identifiedByTOC: true,
			diffID:          "sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			tocDigest:       "sha512:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			expected:        "sha512:0263be0fd3b851ffe02c877574d1d2b19625e36888e63eec2682de2210b6bbaea262e04085843eda16b7014fd59db6aafa0628c2a02443111ae568ea545b112e",
		},
	} {
		origAlg := supporteddigests.TmpDigestForNewObjects()
		defer func() {
			err := supporteddigests.TmpSetDigestForNewObjects(origAlg)
			require.NoError(t, err)
		}()

		err := supporteddigests.TmpSetDigestForNewObjects(c.algorithm)
		require.NoError(t, err)

		var diffID, tocDigest digest.Digest
		if c.diffID != "" {
			diffID, err = digest.Parse(c.diffID)
			require.NoError(t, err)
		}
		if c.tocDigest != "" {
			tocDigest, err = digest.Parse(c.tocDigest)
			require.NoError(t, err)
		}

		res := layerID(c.parentID, trustedLayerIdentityData{
			layerIdentifiedByTOC: c.identifiedByTOC,
			diffID:               diffID,
			tocDigest:            tocDigest,
			blobDigest:           "",
		})
		assert.Equal(t, c.expected, res)
		// blobDigest does not affect the layer ID
		res = layerID(c.parentID, trustedLayerIdentityData{
			layerIdentifiedByTOC: c.identifiedByTOC,
			diffID:               diffID,
			tocDigest:            tocDigest,
			blobDigest:           c.blobDigest,
		})
		assert.Equal(t, c.expected, res)
	}
}

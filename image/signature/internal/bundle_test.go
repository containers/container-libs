package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadBundle tests bundle parsing from JSON bytes.
func TestLoadBundle(t *testing.T) {
	// Valid MessageSignature bundle
	t.Run("valid MessageSignature bundle", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		require.NotNil(t, bundle)
		assert.True(t, bundle.IsMessageSignature())
		assert.False(t, bundle.IsDSSE())
	})

	// Valid DSSE bundle
	t.Run("valid DSSE bundle", func(t *testing.T) {
		bundleJSON := createTestDSSEBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		require.NotNil(t, bundle)
		assert.True(t, bundle.IsDSSE())
		assert.False(t, bundle.IsMessageSignature())
	})

	// Invalid JSON
	t.Run("invalid JSON", func(t *testing.T) {
		_, err := LoadBundle([]byte("not valid json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing sigstore bundle")
	})

	// Empty JSON object - sigstore-go validates media type
	t.Run("empty JSON object", func(t *testing.T) {
		_, err := LoadBundle([]byte("{}"))
		// sigstore-go validates the bundle and requires a valid media type
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing sigstore bundle")
	})
}

// TestBundleRawBytes tests that RawBytes returns the original JSON.
func TestBundleRawBytes(t *testing.T) {
	bundleJSON := createTestMessageSignatureBundle(t)
	bundle, err := LoadBundle(bundleJSON)
	require.NoError(t, err)
	assert.Equal(t, bundleJSON, bundle.RawBytes())
}

// TestBundleIsDSSE tests the IsDSSE helper.
func TestBundleIsDSSE(t *testing.T) {
	t.Run("MessageSignature bundle", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.False(t, bundle.IsDSSE())
	})

	t.Run("DSSE bundle", func(t *testing.T) {
		bundleJSON := createTestDSSEBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.True(t, bundle.IsDSSE())
	})
}

// TestBundleIsMessageSignature tests the IsMessageSignature helper.
func TestBundleIsMessageSignature(t *testing.T) {
	t.Run("MessageSignature bundle", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.True(t, bundle.IsMessageSignature())
	})

	t.Run("DSSE bundle", func(t *testing.T) {
		bundleJSON := createTestDSSEBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.False(t, bundle.IsMessageSignature())
	})
}

// TestBundleGetCertificatePEM tests certificate extraction.
func TestBundleGetCertificatePEM(t *testing.T) {
	t.Run("bundle with certificate", func(t *testing.T) {
		bundleJSON := createTestBundleWithCertificate(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		certPEM, err := bundle.GetCertificatePEM()
		require.NoError(t, err)
		require.NotNil(t, certPEM)

		// Verify it's valid PEM
		block, _ := pem.Decode(certPEM)
		require.NotNil(t, block)
		assert.Equal(t, "CERTIFICATE", block.Type)
	})

	t.Run("bundle without certificate", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		certPEM, err := bundle.GetCertificatePEM()
		require.NoError(t, err)
		assert.Nil(t, certPEM)
	})
}

// TestBundleGetIntermediateChainPEM tests intermediate chain extraction.
func TestBundleGetIntermediateChainPEM(t *testing.T) {
	t.Run("bundle with chain", func(t *testing.T) {
		bundleJSON := createTestBundleWithCertChain(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		chainPEM, err := bundle.GetIntermediateChainPEM()
		require.NoError(t, err)
		require.NotNil(t, chainPEM)

		// Verify it's valid PEM
		block, _ := pem.Decode(chainPEM)
		require.NotNil(t, block)
		assert.Equal(t, "CERTIFICATE", block.Type)
	})

	t.Run("bundle without chain", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		chainPEM, err := bundle.GetIntermediateChainPEM()
		require.NoError(t, err)
		assert.Nil(t, chainPEM)
	})
}

// TestBundleHasTlogEntry tests tlog entry detection.
func TestBundleHasTlogEntry(t *testing.T) {
	// Note: Creating valid tlog entries requires proper formatting that
	// sigstore-go validates strictly. We test the detection on bundles
	// that don't have tlog entries.
	t.Run("bundle without tlog entry", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)
		assert.False(t, bundle.HasTlogEntry())
	})
}

// TestBundleGetIntegratedTime tests integrated time extraction.
func TestBundleGetIntegratedTime(t *testing.T) {
	// Note: Creating valid tlog entries requires proper formatting that
	// sigstore-go validates strictly. We test only the case without tlog entries.
	t.Run("bundle without tlog entry", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		intTime, err := bundle.GetIntegratedTime()
		require.NoError(t, err)
		assert.True(t, intTime.IsZero())
	})
}

// TestBundleGetEnvelopePayload tests DSSE envelope payload extraction.
func TestBundleGetEnvelopePayload(t *testing.T) {
	t.Run("DSSE bundle", func(t *testing.T) {
		bundleJSON := createTestDSSEBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		payload, payloadType, err := bundle.GetEnvelopePayload()
		require.NoError(t, err)
		require.NotNil(t, payload)
		assert.NotEmpty(t, payloadType)
	})

	t.Run("MessageSignature bundle", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		payload, payloadType, err := bundle.GetEnvelopePayload()
		require.NoError(t, err)
		assert.Nil(t, payload)
		assert.Empty(t, payloadType)
	})
}

// TestBundleGetMessageSignatureBytes tests message signature extraction.
func TestBundleGetMessageSignatureBytes(t *testing.T) {
	t.Run("MessageSignature bundle", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		sig, digest, err := bundle.GetMessageSignatureBytes()
		require.NoError(t, err)
		require.NotNil(t, sig)
		require.NotNil(t, digest)
	})

	t.Run("DSSE bundle", func(t *testing.T) {
		bundleJSON := createTestDSSEBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		sig, digest, err := bundle.GetMessageSignatureBytes()
		require.NoError(t, err)
		assert.Nil(t, sig)
		assert.Nil(t, digest)
	})
}

// TestBundleString tests the String representation.
func TestBundleString(t *testing.T) {
	bundleJSON := createTestMessageSignatureBundle(t)
	bundle, err := LoadBundle(bundleJSON)
	require.NoError(t, err)

	str := bundle.String()
	assert.Contains(t, str, "Bundle{")
	assert.Contains(t, str, "isDSSE=")
}

// TestComputePAE tests Pre-Authentication Encoding computation.
func TestComputePAE(t *testing.T) {
	payloadType := "application/vnd.in-toto+json"
	payload := []byte(`{"test": "data"}`)

	pae := ComputePAE(payloadType, payload)

	// Verify PAE format: "DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>"
	// "application/vnd.in-toto+json" is 28 characters
	expected := "DSSEv1 28 application/vnd.in-toto+json 16 {\"test\": \"data\"}"
	assert.Equal(t, expected, string(pae))
}

// TestConvertBundleToLegacyFormat tests conversion to legacy format.
func TestConvertBundleToLegacyFormat(t *testing.T) {
	t.Run("MessageSignature bundle", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		_, base64Sig, payload, err := ConvertBundleToLegacyFormat(bundle)
		require.NoError(t, err)
		assert.NotEmpty(t, base64Sig)
		assert.NotNil(t, payload)
	})

	t.Run("DSSE bundle", func(t *testing.T) {
		bundleJSON := createTestDSSEBundle(t)
		bundle, err := LoadBundle(bundleJSON)
		require.NoError(t, err)

		_, base64Sig, payload, err := ConvertBundleToLegacyFormat(bundle)
		require.NoError(t, err)
		assert.NotEmpty(t, base64Sig)
		assert.NotNil(t, payload)
	})
}

// TestVerifyBundle tests bundle verification with public keys.
func TestVerifyBundle(t *testing.T) {
	t.Run("no verification method", func(t *testing.T) {
		bundleJSON := createTestMessageSignatureBundle(t)
		_, err := VerifyBundle(bundleJSON, BundleVerifyOptions{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no verification method available")
	})

	// Note: Full signature verification tests require properly signed bundles
	// which are tested in the integration tests with real fixtures
}

// Helper functions to create test bundles

// createTestMessageSignatureBundle creates a minimal valid MessageSignature bundle.
func createTestMessageSignatureBundle(t *testing.T) []byte {
	t.Helper()

	// Create a test digest
	testData := []byte("test manifest data")
	hash := sha256.Sum256(testData)

	// Create a test signature (not cryptographically valid, just for parsing tests)
	testSig := []byte("test-signature-bytes")

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{
				"hint": "test-key-hint",
			},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(hash[:]),
			},
			"signature": base64.StdEncoding.EncodeToString(testSig),
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// createTestDSSEBundle creates a minimal valid DSSE bundle.
func createTestDSSEBundle(t *testing.T) []byte {
	t.Helper()

	// Create a simple signing payload
	payload := map[string]any{
		"critical": map[string]any{
			"type": "cosign container image signature",
			"image": map[string]string{
				"docker-manifest-digest": "sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00",
			},
			"identity": map[string]string{
				"docker-reference": "example.com/test:latest",
			},
		},
		"optional": nil,
	}
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)

	// Create a test signature
	testSig := []byte("test-dsse-signature")

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{
				"hint": "test-key-hint",
			},
		},
		"dsseEnvelope": map[string]any{
			"payload":     base64.StdEncoding.EncodeToString(payloadBytes),
			"payloadType": "application/vnd.dev.cosign.simplesigning.v1+json",
			"signatures": []map[string]any{
				{
					"sig":   base64.StdEncoding.EncodeToString(testSig),
					"keyid": "test-key-id",
				},
			},
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// createTestBundleWithCertificate creates a bundle with a certificate.
func createTestBundleWithCertificate(t *testing.T) []byte {
	t.Helper()

	// Generate a test certificate
	certDER := generateTestCertificate(t)

	// Create a test digest
	testData := []byte("test manifest data")
	hash := sha256.Sum256(testData)
	testSig := []byte("test-signature-bytes")

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"x509CertificateChain": map[string]any{
				"certificates": []map[string]any{
					{
						"rawBytes": base64.StdEncoding.EncodeToString(certDER),
					},
				},
			},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(hash[:]),
			},
			"signature": base64.StdEncoding.EncodeToString(testSig),
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// createTestBundleWithCertChain creates a bundle with a certificate chain.
func createTestBundleWithCertChain(t *testing.T) []byte {
	t.Helper()

	// Generate test certificates
	certDER := generateTestCertificate(t)
	intermediateDER := generateTestCertificate(t) // Use same for simplicity

	// Create a test digest
	testData := []byte("test manifest data")
	hash := sha256.Sum256(testData)
	testSig := []byte("test-signature-bytes")

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"x509CertificateChain": map[string]any{
				"certificates": []map[string]any{
					{
						"rawBytes": base64.StdEncoding.EncodeToString(certDER),
					},
					{
						"rawBytes": base64.StdEncoding.EncodeToString(intermediateDER),
					},
				},
			},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(hash[:]),
			},
			"signature": base64.StdEncoding.EncodeToString(testSig),
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// createTestBundleWithTlog creates a bundle with a transparency log entry.
func createTestBundleWithTlog(t *testing.T) []byte {
	t.Helper()

	// Create a test digest
	testData := []byte("test manifest data")
	hash := sha256.Sum256(testData)
	testSig := []byte("test-signature-bytes")

	integratedTime := time.Now().Unix()

	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{
				"hint": "test-key-hint",
			},
			"tlogEntries": []map[string]any{
				{
					"logIndex":       "12345",
					"logId":          map[string]any{"keyId": base64.StdEncoding.EncodeToString([]byte("test-log-id"))},
					"integratedTime": integratedTime,
					"inclusionPromise": map[string]any{
						"signedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("test-set")),
					},
					"canonicalizedBody": base64.StdEncoding.EncodeToString([]byte("test-body")),
				},
			},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{
				"algorithm": "SHA2_256",
				"digest":    base64.StdEncoding.EncodeToString(hash[:]),
			},
			"signature": base64.StdEncoding.EncodeToString(testSig),
		},
	}

	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	return data
}

// generateTestCertificate generates a self-signed test certificate.
func generateTestCertificate(t *testing.T) []byte {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return certDER
}

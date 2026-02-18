package tlsdetails

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/pkg/cli/basetls"
)

func TestBaseTLSFromOptionalFile(t *testing.T) {
	for _, tc := range []struct {
		path     string
		expected *tls.Config
	}{
		{path: "", expected: nil},
		{
			path: "testdata/all-fields.yaml",
			expected: &tls.Config{
				MinVersion:       tls.VersionTLS12,
				CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256},
				CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.X25519},
			},
		},
		{path: "testdata/empty.yaml", expected: nil},
	} {
		baseTLS, err := BaseTLSFromOptionalFile(tc.path)
		require.NoError(t, err)
		require.NotNil(t, baseTLS)
		assert.Equal(t, tc.expected, baseTLS.TLSConfig())
	}
}

func TestBaseTLSFromFile(t *testing.T) {
	for _, tc := range []struct {
		path     string
		expected *tls.Config
	}{
		{
			path: "testdata/all-fields.yaml",
			expected: &tls.Config{
				MinVersion:       tls.VersionTLS12,
				CipherSuites:     []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256},
				CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.X25519},
			},
		},
		{path: "testdata/empty.yaml", expected: nil},
	} {
		baseTLS, err := BaseTLSFromFile(tc.path)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, baseTLS.TLSConfig())
	}

	for _, path := range []string{
		"/dev/null/this/does/not/exist",
		"testdata/invalid-values.yaml",
	} {
		_, err := BaseTLSFromFile(path)
		assert.Error(t, err, path)
		t.Logf("error: %v", err)
	}
}

func TestParseFile(t *testing.T) {
	// A minimal test of parsing; field validation and handling is a responsibility of pkg/cli/basetls.
	for _, tc := range []struct {
		path     string
		expected basetls.TLSDetailsFile
	}{
		{
			path: "testdata/all-fields.yaml",
			expected: basetls.TLSDetailsFile{
				MinVersion:   "1.2",
				CipherSuites: []string{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"},
				NamedGroups:  []string{"secp256r1", "secp384r1", "x25519"},
			},
		},
		{
			path: "testdata/empty-fields.yaml",
			expected: basetls.TLSDetailsFile{
				MinVersion:   "",
				CipherSuites: []string{},
				NamedGroups:  []string{},
			},
		},
		{
			path:     "testdata/empty.yaml",
			expected: basetls.TLSDetailsFile{},
		},
	} {
		f, err := ParseFile(tc.path)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, *f)
	}

	_, err := ParseFile("/dev/null/this/does/not/exist")
	assert.Error(t, err)

	for _, yaml := range []string{
		`minVersion: {}`,                  // not a string; (number-like text is auto-converted)
		`cipherSuites: "not-an-array"`,    // not a list of strings
		`this-field-does-not-exist: true`, // unknown field
		"minVersion: 1\nminVersion: 1.2",  // duplicate field
	} {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		err := os.WriteFile(path, []byte(yaml), 0o600)
		require.NoError(t, err)
		_, err = ParseFile(path)
		assert.Error(t, err, yaml)
	}
}

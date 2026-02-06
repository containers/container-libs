package tlsdetails

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFile(t *testing.T) {
	// A minimal test of parsing; field validation and handling is a responsibility of pkg/cli/basetls.
	for _, tc := range []struct {
		path     string
		expected TLSDetailsFile
	}{
		{
			path: "testdata/all-fields.yaml",
			expected: TLSDetailsFile{
				MinVersion:   "1.2",
				CipherSuites: []string{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"},
				NamedGroups:  []string{"secp256r1", "secp384r1", "x25519"},
			},
		},
		{
			path: "testdata/empty-fields.yaml",
			expected: TLSDetailsFile{
				MinVersion:   "",
				CipherSuites: []string{},
				NamedGroups:  []string{},
			},
		},
		{
			path:     "testdata/empty.yaml",
			expected: TLSDetailsFile{},
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

package basetls

import (
	"crypto/tls"
	"encoding"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	_ encoding.TextMarshaler   = Config{}
	_ encoding.TextMarshaler   = (*Config)(nil)
	_ encoding.TextUnmarshaler = (*Config)(nil)
)

func TestNewFromTLSDetails(t *testing.T) {
	// This tests both the initial parsing, and marshaling+unmarshaling.
	for _, tc := range []struct {
		details  TLSDetailsFile
		expected *tls.Config
	}{
		{
			details:  TLSDetailsFile{MinVersion: "1.2", CipherSuites: []string{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"}, NamedGroups: []string{"secp256r1", "secp384r1", "x25519"}},
			expected: &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256}, CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.X25519}},
		},
	} {
		baseTLS, err := NewFromTLSDetails(&tc.details)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, baseTLS.TLSConfig())

		marshaled, err := baseTLS.MarshalText()
		require.NoError(t, err)
		var unmarshaled Config
		err = unmarshaled.UnmarshalText(marshaled)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, unmarshaled.TLSConfig())

		marshaled2, err := unmarshaled.MarshalText()
		require.NoError(t, err)
		assert.Equal(t, marshaled, marshaled2) // NOT an API promise, and this assumes JSON marshaling is deterministic
		var unmarshaled2 Config
		err = unmarshaled2.UnmarshalText(marshaled2)
		require.NoError(t, err)
		assert.Equal(t, baseTLS.TLSConfig(), unmarshaled2.TLSConfig())
	}
}

func TestBaseTLSParseMinVersion(t *testing.T) {
	for _, tc := range []struct {
		version     string
		expected    *tls.Config
		expectError bool
	}{
		{"", nil, false},
		{"1.0", &tls.Config{MinVersion: tls.VersionTLS10}, false},
		{"1.1", &tls.Config{MinVersion: tls.VersionTLS11}, false},
		{"1.2", &tls.Config{MinVersion: tls.VersionTLS12}, false},
		{"1.3", &tls.Config{MinVersion: tls.VersionTLS13}, false},
		{"this_is_invalid", nil, true},
	} {
		baseTLS, err := NewFromTLSDetails(&TLSDetailsFile{MinVersion: tc.version})
		if tc.expectError {
			assert.Error(t, err)
		} else {
			require.NoError(t, err)
			assert.Equal(t, tc.expected, baseTLS.TLSConfig())
		}
	}
}

func TestBaseTLSParseCipherSuites(t *testing.T) {
	validSuites := tls.CipherSuites()
	require.True(t, len(validSuites) >= 2)
	suite0, suite1 := validSuites[0], validSuites[1]

	for _, tc := range []struct {
		suites      []string
		expected    *tls.Config
		expectError bool
	}{
		{nil, nil, false}, // empty
		{[]string{}, &tls.Config{CipherSuites: []uint16{}}, false}, // no cipher suites
		{[]string{suite0.Name}, &tls.Config{CipherSuites: []uint16{suite0.ID}}, false},
		{[]string{suite0.Name, suite1.Name}, &tls.Config{CipherSuites: []uint16{suite0.ID, suite1.ID}}, false},
		{[]string{"this_is_invalid"}, nil, true},
	} {
		baseTLS, err := NewFromTLSDetails(&TLSDetailsFile{CipherSuites: tc.suites})
		if tc.expectError {
			assert.Error(t, err)
		} else {
			require.NoError(t, err)
			assert.Equal(t, tc.expected, baseTLS.TLSConfig())
		}
	}
}

func TestBaseTLSParseNamedGroups(t *testing.T) {
	for _, tc := range []struct {
		groups      []string
		expected    *tls.Config
		expectError bool
	}{
		{nil, nil, false}, // empty
		{[]string{}, &tls.Config{CurvePreferences: []tls.CurveID{}}, false}, // no named groups
		{[]string{"x25519"}, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}}, false},
		{[]string{"secp256r1"}, &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP256}}, false},
		{[]string{"secp384r1"}, &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP384}}, false},
		{[]string{"secp521r1"}, &tls.Config{CurvePreferences: []tls.CurveID{tls.CurveP521}}, false},
		{[]string{"x25519", "secp256r1"}, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}, false},
		{[]string{"this_is_invalid"}, nil, true},
	} {
		baseTLS, err := NewFromTLSDetails(&TLSDetailsFile{NamedGroups: tc.groups})
		if tc.expectError {
			assert.Error(t, err)
		} else {
			require.NoError(t, err)
			assert.Equal(t, tc.expected, baseTLS.TLSConfig())
		}
	}
}

func TestBaseTLSUnmarshalText(t *testing.T) {
	// General correctness and round-trip safety is tested in TestNewFromTLSDetails.
	for _, json := range []string{
		`&not a valid JSON`,
		`{}`, // missing version
		`{"Version": 9999, "Data":{}}`,
		`{"Version": 1, "Data":{}}{"Version": 1, "Data":{}}`,
		`{"Version": 1, "Data":{ "MinVersion": "this_is_invalid" }}`,
	} {
		var baseTLS Config
		err := baseTLS.UnmarshalText([]byte(json))
		assert.Error(t, err, json)
		t.Logf("error: %v", err)
	}
}

package copy

import (
	"bytes"
	"io"
	"testing"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDigestingReader(t *testing.T) {
	// Only the failure cases, success is tested in TestDigestingReaderRead below.
	source := bytes.NewReader([]byte("abc"))
	for _, input := range []digest.Digest{
		"abc",             // Not algo:hexvalue
		"crc32:",          // Unknown algorithm, empty value
		"crc32:012345678", // Unknown algorithm
		"sha256:",         // Empty value
		"sha256:0",        // Invalid hex value
		"sha256:01",       // Invalid length of hex value
	} {
		_, err := newDigestingReader(source, input)
		assert.Error(t, err, input.String())
	}
}

func TestDigestingReaderRead(t *testing.T) {
	cases := []struct {
		input  []byte
		digest digest.Digest
	}{
		// SHA256 test cases
		{[]byte(""), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{[]byte("abc"), "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{make([]byte, 65537), "sha256:3266304f31be278d06c3bd3eb9aa3e00c59bedec0a890de466568b0b90b0e01f"},
		// SHA512 test cases
		{[]byte(""), "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
		{[]byte("abc"), "sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
		{make([]byte, 65537), "sha512:490821004e5a6025fe335a11f6c27b0f73cae0434bd9d2e5ac7aee3370bd421718cad7d8fbfd5f39153b6ca3b05faede68f5d6e462eeaf143bb034791ceb72ab"},
	}
	// Valid input
	for _, c := range cases {
		source := bytes.NewReader(c.input)
		reader, err := newDigestingReader(source, c.digest)
		require.NoError(t, err, c.digest.String())
		dest := bytes.Buffer{}
		n, err := io.Copy(&dest, reader)
		assert.NoError(t, err, c.digest.String())
		assert.Equal(t, int64(len(c.input)), n, c.digest.String())
		assert.Equal(t, c.input, dest.Bytes(), c.digest.String())
		assert.False(t, reader.validationFailed, c.digest.String())
		assert.True(t, reader.validationSucceeded, c.digest.String())
	}
	// Modified input
	for _, c := range cases {
		source := bytes.NewReader(bytes.Join([][]byte{c.input, []byte("x")}, nil))
		reader, err := newDigestingReader(source, c.digest)
		require.NoError(t, err, c.digest.String())
		dest := bytes.Buffer{}
		_, err = io.Copy(&dest, reader)
		assert.Error(t, err, c.digest.String())
		assert.True(t, reader.validationFailed, c.digest.String())
		assert.False(t, reader.validationSucceeded, c.digest.String())
	}
	// Truncated input
	for _, c := range cases {
		source := bytes.NewReader(c.input)
		reader, err := newDigestingReader(source, c.digest)
		require.NoError(t, err, c.digest.String())
		if len(c.input) != 0 {
			dest := bytes.Buffer{}
			truncatedLen := int64(len(c.input) - 1)
			n, err := io.CopyN(&dest, reader, truncatedLen)
			assert.NoError(t, err, c.digest.String())
			assert.Equal(t, truncatedLen, n, c.digest.String())
		}
		assert.False(t, reader.validationFailed, c.digest.String())
		assert.False(t, reader.validationSucceeded, c.digest.String())
	}
}

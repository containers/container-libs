//go:build containers_image_sequoia

package signature

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSequoiaNewEphemeralGPGSigningMechanism(t *testing.T) {
	// Success is tested in the generic TestNewEphemeralGPGSigningMechanism.

	t.Setenv("SEQUOIA_CRYPTO_POLICY", "this/does/not/exist") // Both unreadable files, and relative paths, should cause an error.
	_, _, err := NewEphemeralGPGSigningMechanism([]byte{})
	assert.Error(t, err)
}

func TestSequoiaSigningMechanismSupportsSigning(t *testing.T) {
	mech, _, err := NewEphemeralGPGSigningMechanism([]byte{})
	require.NoError(t, err)
	defer mech.Close()
	err = mech.SupportsSigning()
	assert.Error(t, err)
	assert.IsType(t, SigningNotSupportedError(""), err)
}

func TestSequoiaSigningMechanismSign(t *testing.T) {
	mech, _, err := NewEphemeralGPGSigningMechanism([]byte{})
	require.NoError(t, err)
	defer mech.Close()
	_, err = mech.Sign([]byte{}, TestKeyFingerprint)
	assert.Error(t, err)
	assert.IsType(t, SigningNotSupportedError(""), err)
}

func TestSequoiaSigningMechanismVerifyCleartext(t *testing.T) {
	mech, err := newGPGSigningMechanismInDirectory(testGPGHomeDirectory)
	require.NoError(t, err)
	defer mech.Close()

	// Successful verification of a cleartext signature
	signature, err := os.ReadFile("./fixtures/invalid-cleartext.signature")
	require.NoError(t, err)
	content, signingFingerprint, err := mech.Verify(signature)
	require.NoError(t, err)
	assert.Equal(t, []byte("This is not JSON\n"), content)
	assert.Equal(t, TestKeyFingerprint, signingFingerprint)
}

package secrets

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// makeReadOnly is used to simulate IO errors like disk full.
func makeReadOnly(t *testing.T, path string) func() {
	t.Helper()
	err := os.Chmod(path, 0o500)
	require.NoError(t, err)

	return func() {
		os.Chmod(path, 0o700)
	}
}

func TestDBRollback(t *testing.T) {
	testSecretName := "testsecret"
	testSecretData := "secretdata"

	t.Run("delete rollback on write failure", func(t *testing.T) {
		manager, driverOpts := setup(t)
		storeOpts := StoreOptions{DriverOpts: driverOpts}

		secretID, err := manager.Store(testSecretName, []byte(testSecretData), drivertype, storeOpts)
		require.NoError(t, err)

		cleanup := makeReadOnly(t, manager.secretsDBPath)
		defer cleanup()

		_, err = manager.Delete(testSecretName)
		require.Error(t, err)

		// Verify rollback: secret should still exist in memory
		require.Equal(t, secretID, manager.db.NameToID[testSecretName])
		require.NotEmpty(t, manager.db.Secrets[secretID])
	})

	t.Run("store rollback on write failure", func(t *testing.T) {
		manager, driverOpts := setup(t)
		storeOpts := StoreOptions{DriverOpts: driverOpts}

		// Make the db file
		_, err := manager.Store("a", []byte("b"), drivertype, storeOpts)
		require.NoError(t, err)
		_, err = manager.Delete("a")
		require.NoError(t, err)

		cleanup := makeReadOnly(t, manager.secretsDBPath)
		defer cleanup()

		_, err = manager.Store(testSecretName, []byte(testSecretData), drivertype, storeOpts)
		require.Error(t, err)

		// Verify rollback: secret should not exist in memory
		require.Empty(t, manager.db.NameToID[testSecretName])
		require.Empty(t, manager.db.Secrets)
	})
}

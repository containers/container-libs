package tempdir

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTempDirAdd(t *testing.T) {
	rootDir := t.TempDir()
	td, err := NewTempDir(rootDir)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, td.Cleanup())
	}()

	filePath := filepath.Join(t.TempDir(), "testfile.txt")
	err = os.WriteFile(filePath, []byte("test content"), 0o644)
	require.NoError(t, err)

	err = td.StageDeletion(filePath)
	require.NoError(t, err)

	assert.NotEmpty(t, td.tempDirPath)
	assert.NotNil(t, td.tempDirLock)
	assert.NotEmpty(t, td.tempDirLockPath)

	files, err := os.ReadDir(td.tempDirPath)
	require.NoError(t, err)
	assert.Len(t, files, 1)
	assert.True(t, strings.HasPrefix(files[0].Name(), "0-"))
	assert.True(t, strings.HasSuffix(files[0].Name(), "testfile.txt"))

	assert.NoFileExists(t, filePath)
}

func TestTempDirAddMultipleFiles(t *testing.T) {
	rootDir := t.TempDir()
	td, err := NewTempDir(rootDir)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, td.Cleanup())
	}()

	tempDir := t.TempDir()

	for i := 0; i < 3; i++ {
		testFile := filepath.Join(tempDir, fmt.Sprintf("testfile%d.txt", i))
		err = os.WriteFile(testFile, []byte(fmt.Sprintf("content %d", i)), 0o644)
		require.NoError(t, err)

		err = td.StageDeletion(testFile)
		require.NoError(t, err)
	}

	files, err := os.ReadDir(td.tempDirPath)
	require.NoError(t, err)
	assert.Len(t, files, 3)

	for i, file := range files {
		assert.Equal(t, filepath.Base(file.Name()), fmt.Sprintf("%d-testfile%d.txt", i, i))
	}
}

func TestTempDirCleanup(t *testing.T) {
	rootDir := t.TempDir()
	td, err := NewTempDir(rootDir)
	require.NoError(t, err)

	testFile := filepath.Join(t.TempDir(), "testfile.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0o644))
	require.NoError(t, td.StageDeletion(testFile))

	tempDirPath := td.tempDirPath
	lockPath := td.tempDirLockPath

	assert.DirExists(t, tempDirPath)
	assert.FileExists(t, lockPath)

	require.NoError(t, td.Cleanup())

	assert.NoDirExists(t, tempDirPath)
	assert.NoFileExists(t, lockPath)

	assert.Empty(t, td.tempDirPath)
	assert.Nil(t, td.tempDirLock)
	assert.Empty(t, td.tempDirLockPath)
}

func TestTempDirCleanupNotInit(t *testing.T) {
	rootDir := t.TempDir()
	td, err := NewTempDir(rootDir)
	require.NoError(t, err)

	assert.NoError(t, td.Cleanup())

	assert.NoError(t, td.Cleanup())
}

func TestTempDirReInitAfterCleanup(t *testing.T) {
	rootDir := t.TempDir()
	td, err := NewTempDir(rootDir)
	require.NoError(t, err)

	testFile1 := filepath.Join(t.TempDir(), "testfile1.txt")
	err = os.WriteFile(testFile1, []byte("test1"), 0o644)
	require.NoError(t, err)

	require.NoError(t, td.StageDeletion(testFile1))

	require.NoError(t, td.Cleanup())

	testFile2 := filepath.Join(t.TempDir(), "testfile2.txt")
	require.NoError(t, os.WriteFile(testFile2, []byte("test2"), 0o644))
	require.Error(t, td.StageDeletion(testFile2))

	assert.Empty(t, td.tempDirPath)
	assert.Nil(t, td.tempDirLock)
}

func TestListPotentialStaleDirs(t *testing.T) {
	rootDir := t.TempDir()

	expectedIds := map[string]struct{}{}

	for range 3 {
		lockfile, err := os.CreateTemp(rootDir, tempdirLockPrefix)
		assert.NoError(t, err)
		lockfileName := filepath.Base(lockfile.Name())
		lockfile.Close()
		id := strings.TrimPrefix(lockfileName, tempdirLockPrefix)
		tempDirPath := filepath.Join(rootDir, tempDirPrefix+id)
		err = os.MkdirAll(tempDirPath, 0o755)
		require.NoError(t, err)
		expectedIds[id] = struct{}{}
	}

	ids, err := listPotentialStaleDirs(rootDir)
	require.NoError(t, err)
	assert.Equal(t, expectedIds, ids)
}

func TestListPotentialStaleDirsNonexistentDir(t *testing.T) {
	nonexistentDir := filepath.Join(t.TempDir(), "nonexistent")

	ids, err := listPotentialStaleDirs(nonexistentDir)
	assert.NoError(t, err)
	assert.Nil(t, ids)
}

func TestRecoverStaleDirs(t *testing.T) {
	rootDir := t.TempDir()

	staleDir := filepath.Join(rootDir, tempDirPrefix+"stale")
	staleLock := filepath.Join(rootDir, tempdirLockPrefix+"stale")

	require.NoError(t, os.MkdirAll(staleDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(staleDir, "somefile"), []byte("data"), 0o644))
	require.NoError(t, os.WriteFile(staleLock, []byte{}, 0o644))

	assert.DirExists(t, staleDir)
	assert.FileExists(t, staleLock)

	assert.NoError(t, RecoverStaleDirs(rootDir))

	assert.NoDirExists(t, staleDir)
	assert.NoFileExists(t, staleLock)
}

func TestRecoverStaleDirsSkipsActiveDirs(t *testing.T) {
	rootDir := t.TempDir()

	td, err := NewTempDir(rootDir)
	require.NoError(t, err)

	testFile := filepath.Join(t.TempDir(), "testfile.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0o644))
	require.NoError(t, td.StageDeletion(testFile))
	defer func() {
		assert.NoError(t, td.Cleanup())
	}()

	activeTempDir := td.tempDirPath
	activeLock := td.tempDirLockPath

	staleDir := filepath.Join(rootDir, tempDirPrefix+"stale")
	staleLock := filepath.Join(rootDir, tempdirLockPrefix+"stale")
	require.NoError(t, os.MkdirAll(staleDir, 0o755))
	require.NoError(t, os.WriteFile(staleLock, []byte{}, 0o644))

	assert.NoError(t, RecoverStaleDirs(rootDir))

	assert.DirExists(t, activeTempDir)
	assert.FileExists(t, activeLock)

	assert.NoDirExists(t, staleDir)
	assert.NoFileExists(t, staleLock)
}

func TestTempDirMultipleInstances(t *testing.T) {
	rootDir := t.TempDir()

	td1, err := NewTempDir(rootDir)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, td1.Cleanup())
	}()

	td2, err := NewTempDir(rootDir)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, td2.Cleanup())
	}()

	testFile1 := filepath.Join(t.TempDir(), "testfile1.txt")
	require.NoError(t, os.WriteFile(testFile1, []byte("test1"), 0o644))
	require.NoError(t, td1.StageDeletion(testFile1))

	testFile2 := filepath.Join(t.TempDir(), "testfile2.txt")
	require.NoError(t, os.WriteFile(testFile2, []byte("test2"), 0o644))
	require.NoError(t, td2.StageDeletion(testFile2))

	assert.NotEqual(t, td1.tempDirPath, td2.tempDirPath)
	assert.NotEqual(t, td1.tempDirLockPath, td2.tempDirLockPath)

	_, err = os.Stat(td1.tempDirPath)
	assert.NoError(t, err)
	_, err = os.Stat(td2.tempDirPath)
	assert.NoError(t, err)
}

func TestTempDirFileNaming(t *testing.T) {
	rootDir := t.TempDir()
	td, err := NewTempDir(rootDir)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, td.Cleanup())
	}()

	tempDir := t.TempDir()

	testCases := []string{
		"simple.txt",
		"file with spaces.txt",
		"file-with-dashes.txt",
		"file.with.dots.txt",
	}

	for i, filename := range testCases {
		testFile := filepath.Join(tempDir, filename)
		require.NoError(t, os.WriteFile(testFile, []byte("test"), 0o644))

		require.NoError(t, td.StageDeletion(testFile))

		files, err := os.ReadDir(td.tempDirPath)
		require.NoError(t, err)

		found := false
		expectedName := fmt.Sprintf("%d-%s", i, filename)
		for _, file := range files {
			if file.Name() == expectedName {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected file %s not found", expectedName)
	}
}

func TestStageAddition(t *testing.T) {
	rootDir := t.TempDir()
	td, err := NewTempDir(rootDir)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, td.Cleanup())
	})

	sa1, err := td.StageAddition()
	require.NoError(t, err)
	// Path should not be created by StagedAddition.
	assert.NoFileExists(t, sa1.Path)

	// ensure we can create file
	f, err := os.Create(sa1.Path)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// need to use a dest file which does not exist yet
	dest := filepath.Join(t.TempDir(), "file1")

	err = sa1.Commit(dest)
	require.NoError(t, err)
	assert.FileExists(t, dest)
	assert.NoFileExists(t, sa1.Path)

	// now test the same with a directory
	sa2, err := td.StageAddition()
	require.NoError(t, err)
	// Path should not be created by StagedAddition.
	assert.NoDirExists(t, sa2.Path)

	// ensure we can create a directory
	err = os.Mkdir(sa2.Path, 0o755)
	require.NoError(t, err)

	// need to use a dest which does not exist yet
	dest = filepath.Join(t.TempDir(), "dir")

	err = sa2.Commit(dest)
	require.NoError(t, err)
	assert.DirExists(t, dest)
	assert.NoDirExists(t, sa2.Path)

	// Commit the same stage addition struct again should error
	err = sa2.Commit(dest)
	require.Error(t, err)

	// Cleanup() should cleanup the temp paths from StagedAddition
	sa3, err := td.StageAddition()
	require.NoError(t, err)

	err = os.Mkdir(sa3.Path, 0o755)
	require.NoError(t, err)

	err = td.Cleanup()
	require.NoError(t, err)
	assert.NoDirExists(t, sa3.Path)
}

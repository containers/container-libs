package storage

import (
	"os"
	"path/filepath"
	"testing"

	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/storage/pkg/idtools"
	"go.podman.io/storage/pkg/reexec"
)

func newTestStore(t *testing.T, testOptions StoreOptions) Store {
	wd := t.TempDir()

	options := testOptions
	if testOptions.RunRoot == "" {
		options.RunRoot = filepath.Join(wd, "run")
	}
	if testOptions.GraphRoot == "" {
		options.GraphRoot = filepath.Join(wd, "root")
	}
	if testOptions.GraphDriverName == "" {
		options.GraphDriverName = "vfs"
	}
	if testOptions.GraphDriverOptions == nil {
		options.GraphDriverOptions = []string{}
	}
	if len(testOptions.UIDMap) == 0 {
		options.UIDMap = []idtools.IDMap{{
			ContainerID: 0,
			HostID:      os.Getuid(),
			Size:        1,
		}}
	}
	if len(testOptions.GIDMap) == 0 {
		options.GIDMap = []idtools.IDMap{{
			ContainerID: 0,
			HostID:      os.Getgid(),
			Size:        1,
		}}
	}

	store, err := GetStore(options)
	require.NoError(t, err)
	return store
}

func TestStore(t *testing.T) {
	pullOpts := map[string]string{"Test1": "test1", "Test2": "test2"}
	store := newTestStore(t, StoreOptions{
		PullOptions: pullOpts,
	})

	root := store.RunRoot()
	require.NotNil(t, root)

	root = store.GraphRoot()
	require.NotNil(t, root)

	root = store.GraphDriverName()
	require.NotNil(t, root)

	gopts := store.GraphOptions()
	assert.Equal(t, []string{}, gopts)

	store.UIDMap()
	store.GIDMap()

	opts := store.PullOptions()
	assert.Equal(t, pullOpts, opts)

	_, err := store.GraphDriver()
	require.Nil(t, err)

	_, err = store.CreateLayer("foo", "bar", nil, "", false, nil)
	require.Error(t, err)

	_, _, err = store.PutLayer("foo", "bar", nil, "", true, nil, nil)
	require.Error(t, err)

	_, err = store.CreateImage("foo", nil, "bar", "", nil)
	require.Error(t, err)

	_, err = store.CreateContainer("foo", nil, "bar", "layer", "", nil)
	require.Error(t, err)

	_, err = store.Metadata("foobar")
	require.Error(t, err)

	err = store.SetMetadata("foo", "bar")
	require.Error(t, err)

	exists := store.Exists("foobar")
	require.False(t, exists)

	_, err = store.Status()
	require.Nil(t, err)

	err = store.Delete("foobar")
	require.Error(t, err)

	err = store.DeleteLayer("foobar")
	require.Error(t, err)

	_, err = store.DeleteImage("foobar", true)
	require.Error(t, err)

	_, err = store.DeleteImage("foobar", false)
	require.Error(t, err)

	err = store.DeleteContainer("foobar")
	require.Error(t, err)

	err = store.DeleteContainer("foobar")
	require.Error(t, err)

	err = store.Wipe()
	require.Nil(t, err)

	_, err = store.Mount("foobar", "")
	require.Error(t, err)

	_, err = store.Unmount("foobar", true)
	require.Error(t, err)

	_, err = store.Unmount("foobar", false)
	require.Error(t, err)

	_, err = store.Mounted("foobar")
	require.Error(t, err)

	_, err = store.Changes("foobar", "foobar")
	require.Error(t, err)

	_, err = store.DiffSize("foobar", "foobar")
	require.Error(t, err)

	_, err = store.Diff("foobar", "foobar", nil)
	require.Error(t, err)

	_, err = store.ApplyDiff("foobar", nil)
	require.Error(t, err)

	var d digest.Digest
	_, err = store.LayersByCompressedDigest(d)
	require.Error(t, err)

	_, err = store.LayersByUncompressedDigest(d)
	require.Error(t, err)

	_, err = store.LayerSize("foobar")
	require.Error(t, err)

	_, _, err = store.LayerParentOwners("foobar")
	require.Error(t, err)

	_, err = store.Layers()
	require.Nil(t, err)

	_, err = store.Images()
	require.Nil(t, err)

	_, err = store.Containers()
	require.Nil(t, err)

	_, err = store.Names("foobar")
	require.Error(t, err)

	err = store.SetNames("foobar", nil)
	require.Error(t, err)

	_, err = store.ListImageBigData("foobar")
	require.Error(t, err)

	_, err = store.ImageBigData("foo", "bar")
	require.Error(t, err)

	_, err = store.ImageBigDataSize("foo", "bar")
	require.Error(t, err)

	_, err = store.ImageBigDataDigest("foo", "bar")
	require.Error(t, err)

	err = store.SetImageBigData("foo", "bar", nil, nil)
	require.Error(t, err)

	_, err = store.ImageSize("foobar")
	require.Error(t, err)

	_, err = store.ListContainerBigData("foobar")
	require.Error(t, err)

	_, err = store.ContainerBigData("foo", "bar")
	require.Error(t, err)

	_, err = store.ContainerBigDataSize("foo", "bar")
	require.Error(t, err)

	_, err = store.ContainerBigDataDigest("foo", "bar")
	require.Error(t, err)

	err = store.SetContainerBigData("foo", "bar", nil)
	require.Error(t, err)

	_, err = store.ContainerSize("foobar")
	require.Error(t, err)

	_, err = store.Layer("foobar")
	require.Error(t, err)

	_, err = store.Image("foobar")
	require.Error(t, err)

	_, err = store.ImagesByTopLayer("foobar")
	require.Error(t, err)

	images, err := store.ImagesByDigest("foobar")
	require.NoError(t, err)
	assert.Equal(t, len(images), 0)

	_, err = store.Container("foobar")
	require.Error(t, err)

	_, err = store.ContainerByLayer("foobar")
	require.Error(t, err)

	_, err = store.ContainerDirectory("foobar")
	require.Error(t, err)

	err = store.SetContainerDirectoryFile("foo", "bar", nil)
	require.Error(t, err)

	_, err = store.FromContainerDirectory("foo", "bar")
	require.Error(t, err)

	_, err = store.ContainerRunDirectory("foobar")
	require.Error(t, err)

	err = store.SetContainerRunDirectoryFile("foo", "bar", nil)
	require.Error(t, err)

	_, err = store.FromContainerRunDirectory("foo", "bar")
	require.Error(t, err)

	_, _, err = store.ContainerParentOwners("foobar")
	require.Error(t, err)

	_, err = store.Lookup("foobar")
	require.Error(t, err)

	_, err = store.Shutdown(false)
	require.Nil(t, err)

	_, err = store.Shutdown(true)
	require.Nil(t, err)

	_, err = store.Version()
	require.Nil(t, err)

	// GetDigestLock returns digest-specific Locker.
	_, err = store.GetDigestLock(d)
	require.Error(t, err)

	store.Free()
	store.Free()
}

func TestWithSplitStore(t *testing.T) {
	wd := t.TempDir()

	pullOpts := map[string]string{"Test1": "test1", "Test2": "test2"}
	store := newTestStore(t, StoreOptions{
		ImageStore:  filepath.Join(wd, "imgstore"),
		PullOptions: pullOpts,
	})

	root := store.RunRoot()
	require.NotNil(t, root)

	root = store.GraphRoot()
	require.NotNil(t, root)

	root = store.GraphDriverName()
	require.NotNil(t, root)

	gopts := store.GraphOptions()
	assert.Equal(t, []string{}, gopts)

	store.UIDMap()
	store.GIDMap()

	opts := store.PullOptions()
	assert.Equal(t, pullOpts, opts)

	_, err := store.GraphDriver()
	require.Nil(t, err)

	_, err = store.CreateLayer("foo", "bar", nil, "", false, nil)
	require.Error(t, err)

	_, _, err = store.PutLayer("foo", "bar", nil, "", true, nil, nil)
	require.Error(t, err)

	_, err = store.CreateImage("foo", nil, "bar", "", nil)
	require.Error(t, err)

	_, err = store.CreateContainer("foo", nil, "bar", "layer", "", nil)
	require.Error(t, err)

	_, err = store.Metadata("foobar")
	require.Error(t, err)

	err = store.SetMetadata("foo", "bar")
	require.Error(t, err)

	exists := store.Exists("foobar")
	require.False(t, exists)

	_, err = store.Status()
	require.Nil(t, err)

	err = store.Delete("foobar")
	require.Error(t, err)

	err = store.DeleteLayer("foobar")
	require.Error(t, err)

	_, err = store.DeleteImage("foobar", true)
	require.Error(t, err)

	_, err = store.DeleteImage("foobar", false)
	require.Error(t, err)

	err = store.DeleteContainer("foobar")
	require.Error(t, err)

	err = store.DeleteContainer("foobar")
	require.Error(t, err)

	err = store.Wipe()
	require.Nil(t, err)

	_, err = store.Mount("foobar", "")
	require.Error(t, err)

	_, err = store.Unmount("foobar", true)
	require.Error(t, err)

	_, err = store.Unmount("foobar", false)
	require.Error(t, err)

	_, err = store.Mounted("foobar")
	require.Error(t, err)

	_, err = store.Changes("foobar", "foobar")
	require.Error(t, err)

	_, err = store.DiffSize("foobar", "foobar")
	require.Error(t, err)

	_, err = store.Diff("foobar", "foobar", nil)
	require.Error(t, err)

	_, err = store.ApplyDiff("foobar", nil)
	require.Error(t, err)

	var d digest.Digest
	_, err = store.LayersByCompressedDigest(d)
	require.Error(t, err)

	_, err = store.LayersByUncompressedDigest(d)
	require.Error(t, err)

	_, err = store.LayerSize("foobar")
	require.Error(t, err)

	_, _, err = store.LayerParentOwners("foobar")
	require.Error(t, err)

	_, err = store.Layers()
	require.Nil(t, err)

	_, err = store.Images()
	require.Nil(t, err)

	_, err = store.Containers()
	require.Nil(t, err)

	_, err = store.Names("foobar")
	require.Error(t, err)

	err = store.SetNames("foobar", nil)
	require.Error(t, err)

	_, err = store.ListImageBigData("foobar")
	require.Error(t, err)

	_, err = store.ImageBigData("foo", "bar")
	require.Error(t, err)

	_, err = store.ImageBigDataSize("foo", "bar")
	require.Error(t, err)

	_, err = store.ImageBigDataDigest("foo", "bar")
	require.Error(t, err)

	err = store.SetImageBigData("foo", "bar", nil, nil)
	require.Error(t, err)

	_, err = store.ImageSize("foobar")
	require.Error(t, err)

	_, err = store.ListContainerBigData("foobar")
	require.Error(t, err)

	_, err = store.ContainerBigData("foo", "bar")
	require.Error(t, err)

	_, err = store.ContainerBigDataSize("foo", "bar")
	require.Error(t, err)

	_, err = store.ContainerBigDataDigest("foo", "bar")
	require.Error(t, err)

	err = store.SetContainerBigData("foo", "bar", nil)
	require.Error(t, err)

	_, err = store.ContainerSize("foobar")
	require.Error(t, err)

	_, err = store.Layer("foobar")
	require.Error(t, err)

	_, err = store.Image("foobar")
	require.Error(t, err)

	_, err = store.ImagesByTopLayer("foobar")
	require.Error(t, err)

	images, err := store.ImagesByDigest("foobar")
	require.NoError(t, err)
	assert.Equal(t, len(images), 0)

	_, err = store.Container("foobar")
	require.Error(t, err)

	_, err = store.ContainerByLayer("foobar")
	require.Error(t, err)

	_, err = store.ContainerDirectory("foobar")
	require.Error(t, err)

	err = store.SetContainerDirectoryFile("foo", "bar", nil)
	require.Error(t, err)

	_, err = store.FromContainerDirectory("foo", "bar")
	require.Error(t, err)

	_, err = store.ContainerRunDirectory("foobar")
	require.Error(t, err)

	err = store.SetContainerRunDirectoryFile("foo", "bar", nil)
	require.Error(t, err)

	_, err = store.FromContainerRunDirectory("foo", "bar")
	require.Error(t, err)

	_, _, err = store.ContainerParentOwners("foobar")
	require.Error(t, err)

	_, err = store.Lookup("foobar")
	require.Error(t, err)

	_, err = store.Shutdown(false)
	require.Nil(t, err)

	_, err = store.Shutdown(true)
	require.Nil(t, err)

	_, err = store.Version()
	require.Nil(t, err)

	// GetDigestLock returns digest-specific Locker.
	_, err = store.GetDigestLock(d)
	require.Error(t, err)

	store.Free()
	store.Free()
}

func TestStoreMultiList(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{})

	_, err := store.CreateLayer("Layer", "", nil, "", false, nil)
	require.NoError(t, err)

	_, err = store.CreateImage("Image", nil, "Layer", "", nil)
	require.NoError(t, err)

	_, err = store.CreateContainer("Container", nil, "Image", "", "", nil)
	require.NoError(t, err)

	tests := []struct {
		options         MultiListOptions
		layerCounts     int
		imageCounts     int
		containerCounts int
	}{
		{
			options: MultiListOptions{
				Layers:     true,
				Images:     true,
				Containers: true,
			},
			layerCounts:     3,
			imageCounts:     1,
			containerCounts: 1,
		},

		{
			options: MultiListOptions{
				Layers:     true,
				Images:     false,
				Containers: false,
			},
			layerCounts:     3,
			imageCounts:     0,
			containerCounts: 0,
		},

		{
			options: MultiListOptions{
				Layers:     false,
				Images:     true,
				Containers: false,
			},
			layerCounts:     0,
			imageCounts:     1,
			containerCounts: 0,
		},

		{
			options: MultiListOptions{
				Layers:     false,
				Images:     false,
				Containers: true,
			},
			layerCounts:     0,
			imageCounts:     0,
			containerCounts: 1,
		},
	}

	for _, test := range tests {
		listResults, err := store.MultiList(test.options)
		require.NoError(t, err)
		require.Len(t, listResults.Layers, test.layerCounts)
		require.Len(t, listResults.Images, test.imageCounts)
		require.Len(t, listResults.Containers, test.containerCounts)
	}

	_, err = store.Shutdown(true)
	require.Nil(t, err)

	store.Free()
}

func TestStoreDelete(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{})

	options := MultiListOptions{
		Layers:     true,
		Images:     true,
		Containers: true,
	}

	expectedResult, err := store.MultiList(options)
	require.NoError(t, err)

	_, err = store.CreateLayer("LayerNoUsed", "", []string{"not-used"}, "", false, nil)
	require.NoError(t, err)

	_, err = store.CreateLayer("Layer", "", []string{"l1"}, "", false, nil)
	require.NoError(t, err)

	_, err = store.CreateImage("Image1", []string{"i1"}, "Layer", "", nil)
	require.NoError(t, err)

	_, err = store.CreateImage("Image", []string{"i"}, "Layer", "", nil)
	require.NoError(t, err)

	_, err = store.CreateContainer("Container", []string{"c"}, "Image", "", "", nil)
	require.NoError(t, err)

	_, err = store.CreateContainer("Container1", []string{"c1"}, "Image1", "", "", nil)
	require.NoError(t, err)

	err = store.DeleteContainer("Container")
	require.NoError(t, err)

	_, err = store.DeleteImage("Image", true)
	require.NoError(t, err)

	err = store.DeleteContainer("Container1")
	require.NoError(t, err)

	_, err = store.DeleteImage("Image1", true)
	require.NoError(t, err)

	err = store.DeleteLayer("LayerNoUsed")
	require.NoError(t, err)

	listResults, err := store.MultiList(options)
	require.NoError(t, err)

	require.Equal(t, expectedResult.Layers, listResults.Layers)
	require.Equal(t, expectedResult.Containers, listResults.Containers)
	require.Equal(t, expectedResult.Images, listResults.Images)

	_, err = store.Shutdown(true)
	require.Nil(t, err)

	store.Free()
}

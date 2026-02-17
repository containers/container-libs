package types

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.podman.io/storage/pkg/unshare"
	"gotest.tools/v3/assert"
)

func TestInvalidKeyFile(t *testing.T) {
	t.Setenv(storageConfEnv, "./storage_broken.conf")
	content := bytes.NewBufferString("")
	logrus.SetOutput(content)
	defer logrus.SetOutput(os.Stderr)
	logrus.SetLevel(logrus.DebugLevel)
	defer logrus.SetLevel(logrus.InfoLevel)
	var storageOpts StoreOptions
	storageOpts, err := LoadStoreOptions(LoadOptions{})
	require.NoError(t, err)
	assert.Equal(t, storageOpts.RunRoot, "/run/containers/test")

	assert.Equal(t, strings.Contains(content.String(), "Failed to decode the keys [\\\"foo\\\" \\\"storage.options.graphroot\\\"] from \\\"./storage_broken.conf\\\"\""), true)
}

func TestLoadStoreOptions(t *testing.T) {
	t.Setenv(storageConfEnv, "./storage_test.conf")
	var storageOpts StoreOptions
	storageOpts, err := LoadStoreOptions(LoadOptions{})
	require.NoError(t, err)

	assert.Equal(t, storageOpts.RunRoot, "/run/"+strconv.Itoa(unshare.GetRootlessUID())+"/containers/storage")
	assert.Equal(t, storageOpts.GraphRoot, os.Getenv("HOME")+"/"+strconv.Itoa(unshare.GetRootlessUID())+"/containers/storage")
}

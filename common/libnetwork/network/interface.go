//go:build linux || freebsd

package network

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"go.podman.io/common/libnetwork/netavark"
	"go.podman.io/common/libnetwork/types"
	"go.podman.io/common/pkg/config"
	"go.podman.io/storage"
	"go.podman.io/storage/pkg/ioutils"
	"go.podman.io/storage/pkg/unshare"
)

const (
	// defaultNetworkBackendFileName is the file name for sentinel file to store the backend.
	defaultNetworkBackendFileName = "defaultNetworkBackend"

	// netavarkBinary is the name of the netavark binary.
	netavarkBinary = "netavark"
	// aardvarkBinary is the name of the aardvark binary.
	aardvarkBinary = "aardvark-dns"
)

// NetworkBackend returns the network backend name and interface
// It returns netavark backend depending on what is set in the config.
// If the backend is set to "" we will automatically assign the netavark
// backend.
//
// revive does not like the name because the package is already called network
//
//nolint:revive
func NetworkBackend(store storage.Store, conf *config.Config, syslog bool) (types.NetworkBackend, types.ContainerNetwork, error) {
	backend := types.NetworkBackend(conf.Network.NetworkBackend)
	if backend == "" {
		var err error
		backend, err = defaultNetworkBackend(store)
		if err != nil {
			return "", nil, fmt.Errorf("failed to get default network backend: %w", err)
		}
	}

	return backendFromType(backend, store, conf, syslog)
}

func backendFromType(backend types.NetworkBackend, store storage.Store, conf *config.Config, syslog bool) (types.NetworkBackend, types.ContainerNetwork, error) {
	switch backend {
	case types.Netavark:
		netInt, err := netavarkBackendFromConf(store, conf, syslog)
		if err != nil {
			return "", nil, err
		}
		return types.Netavark, netInt, err
	default:
		return "", nil, fmt.Errorf("unsupported network backend %q, check network_backend in containers.conf", backend)
	}
}

func netavarkBackendFromConf(store storage.Store, conf *config.Config, syslog bool) (types.ContainerNetwork, error) {
	netavarkBin, err := conf.FindHelperBinary(netavarkBinary, false)
	if err != nil {
		return nil, err
	}

	aardvarkBin, _ := conf.FindHelperBinary(aardvarkBinary, false)

	confDir := conf.Network.NetworkConfigDir
	if confDir == "" {
		confDir = getDefaultNetavarkConfigDir(store)
	}

	// We cannot use the runroot for rootful since the network namespace is shared for all
	// libpod instances they also have to share the same ipam db.
	// For rootless we have our own network namespace per libpod instances,
	// so this is not a problem there.
	runDir := netavarkRunDir
	if unshare.IsRootless() {
		runDir = filepath.Join(store.RunRoot(), "networks")
	}

	netInt, err := netavark.NewNetworkInterface(&netavark.InitConfig{
		Config:           conf,
		NetworkConfigDir: confDir,
		NetworkRunDir:    runDir,
		NetavarkBinary:   netavarkBin,
		AardvarkBinary:   aardvarkBin,
		Syslog:           syslog,
	})
	return netInt, err
}

func defaultNetworkBackend(store storage.Store) (backend types.NetworkBackend, err error) {
	err = nil

	file := filepath.Join(store.GraphRoot(), defaultNetworkBackendFileName)

	writeBackendToFile := func(backendT types.NetworkBackend) {
		// only write when there is no error
		if err == nil {
			if err := ioutils.AtomicWriteFile(file, []byte(backendT), 0o644); err != nil {
				logrus.Errorf("could not write network backend to file: %v", err)
			}
		}
	}

	// read defaultNetworkBackend file
	b, err := os.ReadFile(file)
	if err == nil {
		val := string(b)

		// set network backend to netavark if not already.
		if val != string(types.Netavark) {
			// netavark is always good
			writeBackendToFile(types.Netavark)
			logrus.Info("Migrating network backend to netavark as no backend has been configured previously")
		}
		return types.Netavark, nil
	}

	// fail for all errors except ENOENT
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("could not read network backend value: %w", err)
	}

	return "", nil
}

// getDefaultNetavarkConfigDir return the netavark config dir. For rootful it will
// use "/etc/containers/networks" and for rootless "$graphroot/networks". We cannot
// use the graphroot for rootful since the network namespace is shared for all
// libpod instances.
func getDefaultNetavarkConfigDir(store storage.Store) string {
	if !unshare.IsRootless() {
		return netavarkConfigDir
	}
	return filepath.Join(store.GraphRoot(), "networks")
}

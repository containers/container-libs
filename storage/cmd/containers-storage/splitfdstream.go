//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"go.podman.io/storage"
	graphdriver "go.podman.io/storage/drivers"
	"go.podman.io/storage/pkg/archive"
	"go.podman.io/storage/pkg/mflag"
	"go.podman.io/storage/pkg/splitfdstream"
)

const defaultJSONRPCSocket = "json-rpc.sock"

var (
	splitfdstreamSocket     = ""
	applyFdstreamSocket     = ""
	applyFdstreamParent     = ""
	applyFdstreamMountLabel = ""
)

// splitFDStreamDiffer implements graphdriver.Differ for splitfdstream data
type splitFDStreamDiffer struct {
	streamData []byte
	fds        []*os.File
	store      storage.Store
}

func (d *splitFDStreamDiffer) ApplyDiff(dest string, options *archive.TarOptions, differOpts *graphdriver.DifferOptions) (graphdriver.DriverWithDifferOutput, error) {
	driver, err := d.store.GraphDriver()
	if err != nil {
		return graphdriver.DriverWithDifferOutput{}, fmt.Errorf("failed to get graph driver: %w", err)
	}

	splitDriver, ok := driver.(splitfdstream.SplitFDStreamDriver)
	if !ok {
		return graphdriver.DriverWithDifferOutput{}, fmt.Errorf("driver %s does not support splitfdstream", driver.String())
	}

	opts := &splitfdstream.ApplySplitFDStreamOpts{
		Stream:          bytes.NewReader(d.streamData),
		FileDescriptors: d.fds,
		StagingDir:      dest,
	}

	size, err := splitDriver.ApplySplitFDStream(opts)
	if err != nil {
		return graphdriver.DriverWithDifferOutput{}, fmt.Errorf("failed to apply splitfdstream to staging dir %s: %w", dest, err)
	}

	return graphdriver.DriverWithDifferOutput{
		Target: dest,
		Size:   size,
	}, nil
}

func (d *splitFDStreamDiffer) Close() error {
	return nil
}

func splitfdstreamServer(flags *mflag.FlagSet, action string, m storage.Store, args []string) (int, error) {
	driver, err := m.GraphDriver()
	if err != nil {
		return 1, fmt.Errorf("failed to get graph driver: %w", err)
	}

	splitDriver, ok := driver.(splitfdstream.SplitFDStreamDriver)
	if !ok {
		return 1, fmt.Errorf("driver %s does not support splitfdstream", driver.String())
	}
	server := splitfdstream.NewJSONRPCServer(splitDriver, m)

	socketPath := splitfdstreamSocket
	if socketPath == "" {
		socketPath = filepath.Join(m.RunRoot(), defaultJSONRPCSocket)
	}

	if err := server.Start(socketPath); err != nil {
		return 1, fmt.Errorf("failed to start server: %w", err)
	}
	defer func() { _ = server.Stop() }()

	fmt.Printf("%s\n", socketPath)

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	return 0, nil
}

func applySplitfdstream(flags *mflag.FlagSet, action string, m storage.Store, args []string) (int, error) {
	layerID := args[0]

	socketPath := applyFdstreamSocket
	if socketPath == "" {
		socketPath = filepath.Join(m.RunRoot(), defaultJSONRPCSocket)
	}

	defer func() {
		if _, err := m.Shutdown(false); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to shutdown storage: %v\n", err)
		}
	}()

	client, err := splitfdstream.NewJSONRPCClient(socketPath)
	if err != nil {
		return 1, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer client.Close()

	// Get splitfdstream data from remote server
	streamData, fds, err := client.GetSplitFDStream(layerID, "")
	if err != nil {
		return 1, fmt.Errorf("failed to get splitfdstream from server: %w", err)
	}

	// Close received FDs when done
	defer func() {
		for _, fd := range fds {
			fd.Close()
		}
	}()

	// Create a custom differ for splitfdstream data
	differ := &splitFDStreamDiffer{
		streamData: streamData,
		fds:        fds,
		store:      m,
	}
	defer differ.Close()

	// Prepare the staged layer
	diffOptions := &graphdriver.ApplyDiffWithDifferOpts{}
	diffOutput, err := m.PrepareStagedLayer(diffOptions, differ)
	if err != nil {
		return 1, fmt.Errorf("failed to prepare staged layer: %w", err)
	}

	// Apply the staged layer to create the final layer
	applyArgs := storage.ApplyStagedLayerOptions{
		ID:           layerID,
		ParentLayer:  applyFdstreamParent,
		MountLabel:   applyFdstreamMountLabel,
		Writeable:    false,
		LayerOptions: &storage.LayerOptions{},
		DiffOutput:   diffOutput,
		DiffOptions:  diffOptions,
	}

	layer, err := m.ApplyStagedLayer(applyArgs)
	if err != nil {
		// Clean up the staged layer on failure
		if cleanupErr := m.CleanupStagedLayer(diffOutput); cleanupErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to cleanup staged layer: %v\n", cleanupErr)
		}
		return 1, fmt.Errorf("failed to apply staged layer: %w", err)
	}

	// Output the result
	if jsonOutput {
		return outputJSON(map[string]interface{}{"id": layer.ID, "size": diffOutput.Size})
	}
	fmt.Printf("%s\n", layer.ID)
	return 0, nil
}

func init() {
	commands = append(commands, command{
		names:       []string{"json-rpc-server"},
		optionsHelp: "[options]",
		usage:       "Start a JSON-RPC server",
		minArgs:     0,
		maxArgs:     0,
		action:      splitfdstreamServer,
		addFlags: func(flags *mflag.FlagSet, cmd *command) {
			flags.StringVar(&splitfdstreamSocket, []string{"-socket"}, "",
				"Path to UNIX socket")
		},
	})
	commands = append(commands, command{
		names:       []string{"apply-splitfdstream"},
		optionsHelp: "[options] layerID",
		usage:       "Fetch a layer from remote server and apply it locally",
		minArgs:     1,
		maxArgs:     1,
		action:      applySplitfdstream,
		addFlags: func(flags *mflag.FlagSet, cmd *command) {
			flags.StringVar(&applyFdstreamSocket, []string{"-socket"}, "",
				"Path to remote UNIX socket")
			flags.StringVar(&applyFdstreamParent, []string{"-parent"}, "",
				"Parent layer ID for the new layer")
			flags.StringVar(&applyFdstreamMountLabel, []string{"-mount-label"}, "",
				"SELinux mount label for the layer")
			flags.BoolVar(&jsonOutput, []string{"-json", "j"}, jsonOutput, "Prefer JSON output")
		},
	})
}

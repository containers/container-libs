package main

import (
	"fmt"
	"os"

	"go.podman.io/storage"
	"go.podman.io/storage/pkg/mflag"
	"go.podman.io/storage/types"
)

func config(flags *mflag.FlagSet, action string, m storage.Store, args []string) (int, error) {
	if len(args) > 0 {
		if err := os.Setenv("CONTAINERS_STORAGE_CONF", args[0]); err != nil {
			return 1, fmt.Errorf("setenv: %w", err)
		}
	}
	options, err := types.DefaultStoreOptions()
	if err != nil {
		return 1, fmt.Errorf("load default options: %w", err)
	}
	return outputJSON(options)
}

func init() {
	commands = append(commands, command{
		names:       []string{"config"},
		usage:       "Print storage library configuration as JSON",
		minArgs:     0,
		maxArgs:     1,
		optionsHelp: "[configurationFile]",
		action:      config,
	})
}

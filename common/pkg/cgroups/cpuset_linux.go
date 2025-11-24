//go:build linux

package cgroups

import (
	"github.com/opencontainers/cgroups"
)

type linuxCpusetHandler struct {
}

func getCpusetHandler() *linuxCpusetHandler {
	return &linuxCpusetHandler{}
}

// Stat fills a metrics structure with usage stats for the controller.
func (c *linuxCpusetHandler) Stat(_ *CgroupControl, _ *cgroups.Stats) error {
	return nil
}

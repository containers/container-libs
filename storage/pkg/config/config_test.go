package config

import (
	"strings"
	"testing"
)

const (
	foobar     = "foobar"
	nodev      = "nodev"
	trueString = "true"
	s100       = "100"
	s200       = "200"
)

func searchOptions(options []string, value string) bool {
	for _, s := range options {
		if strings.Contains(s, value) {
			return true
		}
	}
	return false
}

func TestBtrfsOptions(t *testing.T) {
	var (
		doptions []string
		options  OptionsConfig
	)
	doptions = GetGraphDriverOptions(options)
	if len(doptions) != 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	// Make sure legacy mountopt still works
	options = OptionsConfig{}
	options.Btrfs.MinSpace = s100
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	if !searchOptions(doptions, s100) {
		t.Fatalf("Expected to find %q options, got %v", s100, doptions)
	}

	options = OptionsConfig{}
	// Make sure Btrfs.Size takes precedence
	options.Btrfs.Size = s100
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	if !searchOptions(doptions, s100) {
		t.Fatalf("Expected to find size %q, got %v", s100, doptions)
	}
}

func TestOverlayOptions(t *testing.T) {
	var (
		doptions []string
		options  OptionsConfig
	)
	doptions = GetGraphDriverOptions(options)
	if len(doptions) != 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	options.Overlay.IgnoreChownErrors = trueString
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 1 options, got %v", doptions)
	}
	options.Overlay.IgnoreChownErrors = "false"
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}

	// Make sure OverlayMountOpt takes precedence
	options.Overlay.MountOpt = nodev
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	if !searchOptions(doptions, "mountopt=nodev") {
		t.Fatalf("Expected to find 'nodev' options, got %v", doptions)
	}

	options.Overlay.MountProgram = "/usr/bin/fuse_overlay"
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	if !searchOptions(doptions, "mount_program=/usr/bin/fuse_overlay") {
		t.Fatalf("Expected to find 'fuse_overlay' options, got %v", doptions)
	}
	options.Overlay.SkipMountHome = "true"
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	if !searchOptions(doptions, "skip_mount_home") {
		t.Fatalf("Expected to find 'skip_mount_home' options, got %v", doptions)
	}

	options.Overlay.UseComposefs = "true"
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected > 0 options, got %v", doptions)
	}
	if !searchOptions(doptions, "use_composefs") {
		t.Fatalf("Expected to find 'use_composefs' options, got %v", doptions)
	}

	// Make sure Overlay.Size takes precedence
	options.Overlay.Size = s100
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	if !searchOptions(doptions, s100) {
		t.Fatalf("Expected to find size %q, got %v", s100, doptions)
	}
}

func TestVfsOptions(t *testing.T) {
	var (
		doptions []string
		options  OptionsConfig
	)
	doptions = GetGraphDriverOptions(options)
	if len(doptions) != 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	options.Overlay.IgnoreChownErrors = trueString
	doptions = GetGraphDriverOptions(options)
	if len(doptions) != 1 {
		t.Fatalf("Expected 1 options, got %v", doptions)
	}
	options.Vfs.IgnoreChownErrors = trueString
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 1 options, got %v", doptions)
	}
}

func TestZfsOptions(t *testing.T) {
	var (
		doptions []string
		options  OptionsConfig
	)
	doptions = GetGraphDriverOptions(options)
	if len(doptions) != 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	// Make sure legacy mountopt still works
	options = OptionsConfig{}
	options.Zfs.Name = foobar
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	if !searchOptions(doptions, options.Zfs.Name) {
		t.Fatalf("Expected to find 'foobar' options, got %v", doptions)
	}

	// Make sure Zfs.Size takes precedence
	options.Zfs.Size = s100
	doptions = GetGraphDriverOptions(options)
	if len(doptions) == 0 {
		t.Fatalf("Expected 0 options, got %v", doptions)
	}
	if !searchOptions(doptions, s100) {
		t.Fatalf("Expected to find size %q, got %v", s100, doptions)
	}
}

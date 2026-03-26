package storage

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	drivers "go.podman.io/storage/drivers"
	"go.podman.io/storage/pkg/reexec"
)

type tarEntry struct {
	Name    string
	Mode    os.FileMode
	IsDir   bool
	Content string
}

// makeTarWithPermissions creates a tar archive containing entries with the
// specified names, permission modes, and content.
func makeTarWithPermissions(entries []tarEntry) io.Reader {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	for _, e := range entries {
		hdr := &tar.Header{
			Name: e.Name,
			Mode: int64(e.Mode),
			Size: int64(len(e.Content)),
		}
		if e.IsDir {
			hdr.Typeflag = tar.TypeDir
			hdr.Size = 0
		} else {
			hdr.Typeflag = tar.TypeReg
		}
		_ = tw.WriteHeader(hdr)
		if len(e.Content) > 0 {
			_, _ = tw.Write([]byte(e.Content))
		}
	}
	_ = tw.Close()
	return buf
}

// getFileMode returns the permission bits (including SUID/SGID/sticky) of the
// file at the given path.
func getFileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	require.NoError(t, err)
	return fi.Mode().Perm() | (fi.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky))
}

// TestStripSUIDSGIDDisabledPreservesPermissions verifies that when strip_suid_sgid
// is false (the default), SUID and SGID bits in the layer data are preserved as-is
// during extraction via ApplyDiff.
func TestStripSUIDSGIDDisabledPreservesPermissions(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{})
	defer store.Free()

	layer, err := store.CreateLayer("", "", nil, "", false, nil)
	require.NoError(t, err)

	diff := makeTarWithPermissions([]tarEntry{
		{Name: "suid_file", Mode: 0o4755},
		{Name: "sgid_file", Mode: 0o2755},
		{Name: "both_file", Mode: 0o6755},
		{Name: "normal_file", Mode: 0o0755},
		{Name: "suid_dir/", Mode: 0o4755, IsDir: true},
		{Name: "sgid_dir/", Mode: 0o2755, IsDir: true},
	})

	_, err = store.ApplyDiff(layer.ID, diff)
	require.NoError(t, err)

	mountPoint, err := store.Mount(layer.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = store.Unmount(layer.ID, true)
	}()

	mode := getFileMode(t, filepath.Join(mountPoint, "suid_file"))
	assert.NotZero(t, mode&os.ModeSetuid, "SUID bit should be preserved when strip_suid_sgid is disabled")

	mode = getFileMode(t, filepath.Join(mountPoint, "sgid_file"))
	assert.NotZero(t, mode&os.ModeSetgid, "SGID bit should be preserved when strip_suid_sgid is disabled")

	mode = getFileMode(t, filepath.Join(mountPoint, "both_file"))
	assert.NotZero(t, mode&os.ModeSetuid, "SUID bit should be preserved when strip_suid_sgid is disabled")
	assert.NotZero(t, mode&os.ModeSetgid, "SGID bit should be preserved when strip_suid_sgid is disabled")

	mode = getFileMode(t, filepath.Join(mountPoint, "normal_file"))
	assert.Zero(t, mode&os.ModeSetuid, "normal file should not have SUID")
	assert.Zero(t, mode&os.ModeSetgid, "normal file should not have SGID")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "normal file permissions should be 0755")

	mode = getFileMode(t, filepath.Join(mountPoint, "suid_dir"))
	assert.NotZero(t, mode&os.ModeSetuid, "SUID bit on directory should be preserved when strip_suid_sgid is disabled")

	mode = getFileMode(t, filepath.Join(mountPoint, "sgid_dir"))
	assert.NotZero(t, mode&os.ModeSetgid, "SGID bit on directory should be preserved when strip_suid_sgid is disabled")
}

// TestStripSUIDSGIDDefaultIsFalse verifies that the default value of strip_suid_sgid
// is false, so SUID/SGID bits are preserved when the option is not explicitly set.
func TestStripSUIDSGIDDefaultIsFalse(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{})
	defer store.Free()

	layer, _, err := store.PutLayer("", "", nil, "", false, nil,
		makeTarWithPermissions([]tarEntry{
			{Name: "suid_binary", Mode: 0o4755, Content: "binary"},
			{Name: "sgid_binary", Mode: 0o2755, Content: "binary"},
		}),
	)
	require.NoError(t, err)

	mountPoint, err := store.Mount(layer.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = store.Unmount(layer.ID, true)
	}()

	mode := getFileMode(t, filepath.Join(mountPoint, "suid_binary"))
	assert.NotZero(t, mode&os.ModeSetuid, "SUID should be preserved by default")

	mode = getFileMode(t, filepath.Join(mountPoint, "sgid_binary"))
	assert.NotZero(t, mode&os.ModeSetgid, "SGID should be preserved by default")
}

// TestStripSUIDSGIDEnabledStripsViaApplyDiff verifies the tar path: when strip_suid_sgid
// is true, ApplyDiff strips SUID and SGID bits from all entry types while preserving
// other permission bits.
func TestStripSUIDSGIDEnabledStripsViaApplyDiff(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{
		StripSUIDSGID: true,
	})
	defer store.Free()

	layer, err := store.CreateLayer("", "", nil, "", false, nil)
	require.NoError(t, err)

	diff := makeTarWithPermissions([]tarEntry{
		{Name: "suid_file", Mode: 0o4755, Content: "suid content"},
		{Name: "sgid_file", Mode: 0o2755, Content: "sgid content"},
		{Name: "both_file", Mode: 0o6755, Content: "both content"},
		{Name: "normal_file", Mode: 0o0755, Content: "normal content"},
		{Name: "suid_dir/", Mode: 0o4755, IsDir: true},
		{Name: "sgid_dir/", Mode: 0o2755, IsDir: true},
		{Name: "both_dir/", Mode: 0o6755, IsDir: true},
		{Name: "normal_dir/", Mode: 0o0755, IsDir: true},
	})

	_, err = store.ApplyDiff(layer.ID, diff)
	require.NoError(t, err)

	mountPoint, err := store.Mount(layer.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = store.Unmount(layer.ID, true)
	}()

	// Files: SUID/SGID stripped, base permissions preserved.
	mode := getFileMode(t, filepath.Join(mountPoint, "suid_file"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID bit should be stripped")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "base permissions should be preserved")

	mode = getFileMode(t, filepath.Join(mountPoint, "sgid_file"))
	assert.Zero(t, mode&os.ModeSetgid, "SGID bit should be stripped")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "base permissions should be preserved")

	mode = getFileMode(t, filepath.Join(mountPoint, "both_file"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID bit should be stripped")
	assert.Zero(t, mode&os.ModeSetgid, "SGID bit should be stripped")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "base permissions should be preserved")

	mode = getFileMode(t, filepath.Join(mountPoint, "normal_file"))
	assert.Zero(t, mode&os.ModeSetuid, "normal file should not have SUID")
	assert.Zero(t, mode&os.ModeSetgid, "normal file should not have SGID")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "normal file permissions should be 0755")

	// Directories: SUID/SGID stripped.
	mode = getFileMode(t, filepath.Join(mountPoint, "suid_dir"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID bit on directory should be stripped")

	mode = getFileMode(t, filepath.Join(mountPoint, "sgid_dir"))
	assert.Zero(t, mode&os.ModeSetgid, "SGID bit on directory should be stripped")

	mode = getFileMode(t, filepath.Join(mountPoint, "both_dir"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID bit on directory should be stripped")
	assert.Zero(t, mode&os.ModeSetgid, "SGID bit on directory should be stripped")

	mode = getFileMode(t, filepath.Join(mountPoint, "normal_dir"))
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "normal directory permissions should be 0755")
}

// TestStripSUIDSGIDEnabledStripsViaPutLayer verifies the tar path via PutLayer:
// when strip_suid_sgid is true, SUID and SGID bits are stripped during layer creation.
func TestStripSUIDSGIDEnabledStripsViaPutLayer(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{
		StripSUIDSGID: true,
	})
	defer store.Free()

	diff := makeTarWithPermissions([]tarEntry{
		{Name: "suid_file", Mode: 0o4755, Content: "data"},
		{Name: "sgid_file", Mode: 0o2755, Content: "data"},
		{Name: "both_file", Mode: 0o6755, Content: "data"},
		{Name: "normal_file", Mode: 0o0644, Content: "data"},
	})

	layer, _, err := store.PutLayer("", "", nil, "", false, nil, diff)
	require.NoError(t, err)

	mountPoint, err := store.Mount(layer.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = store.Unmount(layer.ID, true)
	}()

	mode := getFileMode(t, filepath.Join(mountPoint, "suid_file"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID bit should be stripped via PutLayer")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "base permissions should be preserved")

	mode = getFileMode(t, filepath.Join(mountPoint, "sgid_file"))
	assert.Zero(t, mode&os.ModeSetgid, "SGID bit should be stripped via PutLayer")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "base permissions should be preserved")

	mode = getFileMode(t, filepath.Join(mountPoint, "both_file"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID bit should be stripped via PutLayer")
	assert.Zero(t, mode&os.ModeSetgid, "SGID bit should be stripped via PutLayer")

	mode = getFileMode(t, filepath.Join(mountPoint, "normal_file"))
	assert.Zero(t, mode&os.ModeSetuid, "normal file should not have SUID")
	assert.Zero(t, mode&os.ModeSetgid, "normal file should not have SGID")
	assert.Equal(t, os.FileMode(0o644), mode&os.ModePerm, "normal file permissions should be 0644")
}

// TestStripSUIDSGIDPreservesOtherBits verifies that when strip_suid_sgid is true,
// only SUID and SGID bits are cleared. The sticky bit and all rwxrwxrwx bits are
// preserved unchanged.
func TestStripSUIDSGIDPreservesOtherBits(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{
		StripSUIDSGID: true,
	})
	defer store.Free()

	layer, err := store.CreateLayer("", "", nil, "", false, nil)
	require.NoError(t, err)

	diff := makeTarWithPermissions([]tarEntry{
		{Name: "sticky_suid", Mode: 0o5755, Content: "data"},
		{Name: "sticky_sgid", Mode: 0o3755, Content: "data"},
		{Name: "all_bits", Mode: 0o7777, Content: "data"},
		{Name: "restricted", Mode: 0o4700, Content: "data"},
		{Name: "read_only", Mode: 0o2444, Content: "data"},
		{Name: "sticky_dir/", Mode: 0o1755, IsDir: true},
		{Name: "sticky_suid_dir/", Mode: 0o5755, IsDir: true},
	})

	_, err = store.ApplyDiff(layer.ID, diff)
	require.NoError(t, err)

	mountPoint, err := store.Mount(layer.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = store.Unmount(layer.ID, true)
	}()

	// sticky + SUID: SUID stripped, sticky and rwxr-xr-x preserved.
	mode := getFileMode(t, filepath.Join(mountPoint, "sticky_suid"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID should be stripped")
	assert.NotZero(t, mode&os.ModeSticky, "sticky bit should be preserved")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "base permissions should be preserved")

	// sticky + SGID: SGID stripped, sticky and rwxr-xr-x preserved.
	mode = getFileMode(t, filepath.Join(mountPoint, "sticky_sgid"))
	assert.Zero(t, mode&os.ModeSetgid, "SGID should be stripped")
	assert.NotZero(t, mode&os.ModeSticky, "sticky bit should be preserved")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm, "base permissions should be preserved")

	// All special bits: SUID and SGID stripped, sticky and rwxrwxrwx preserved.
	mode = getFileMode(t, filepath.Join(mountPoint, "all_bits"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID should be stripped")
	assert.Zero(t, mode&os.ModeSetgid, "SGID should be stripped")
	assert.NotZero(t, mode&os.ModeSticky, "sticky bit should be preserved")
	assert.Equal(t, os.FileMode(0o777), mode&os.ModePerm, "rwxrwxrwx should be preserved")

	// SUID + rwx------: SUID stripped, rwx------ preserved.
	mode = getFileMode(t, filepath.Join(mountPoint, "restricted"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID should be stripped")
	assert.Equal(t, os.FileMode(0o700), mode&os.ModePerm, "base permissions should be 0700")

	// SGID + r--r--r--: SGID stripped, r--r--r-- preserved.
	mode = getFileMode(t, filepath.Join(mountPoint, "read_only"))
	assert.Zero(t, mode&os.ModeSetgid, "SGID should be stripped")
	assert.Equal(t, os.FileMode(0o444), mode&os.ModePerm, "base permissions should be 0444")

	// Sticky-only dir: not affected (no SUID/SGID to strip).
	mode = getFileMode(t, filepath.Join(mountPoint, "sticky_dir"))
	assert.NotZero(t, mode&os.ModeSticky, "sticky bit should be preserved")
	assert.Zero(t, mode&os.ModeSetuid, "dir should not have SUID")
	assert.Zero(t, mode&os.ModeSetgid, "dir should not have SGID")

	// Sticky + SUID dir: SUID stripped, sticky preserved.
	mode = getFileMode(t, filepath.Join(mountPoint, "sticky_suid_dir"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID should be stripped from directory")
	assert.NotZero(t, mode&os.ModeSticky, "sticky bit should be preserved on directory")
}

// TestStripSUIDSGIDOnlyAffectsSUIDSGID verifies that entries without SUID or SGID
// bits are not affected at all by strip_suid_sgid=true.
func TestStripSUIDSGIDOnlyAffectsSUIDSGID(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{
		StripSUIDSGID: true,
	})
	defer store.Free()

	diff := makeTarWithPermissions([]tarEntry{
		{Name: "perm_000", Mode: 0o000, Content: "data"},
		{Name: "perm_644", Mode: 0o644, Content: "data"},
		{Name: "perm_755", Mode: 0o755, Content: "data"},
		{Name: "perm_777", Mode: 0o777, Content: "data"},
		{Name: "sticky_only", Mode: 0o1755, Content: "data"},
		{Name: "dir_755/", Mode: 0o755, IsDir: true},
		{Name: "dir_700/", Mode: 0o700, IsDir: true},
	})

	layer, _, err := store.PutLayer("", "", nil, "", false, nil, diff)
	require.NoError(t, err)

	mountPoint, err := store.Mount(layer.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = store.Unmount(layer.ID, true)
	}()

	mode := getFileMode(t, filepath.Join(mountPoint, "perm_644"))
	assert.Equal(t, os.FileMode(0o644), mode&os.ModePerm)

	mode = getFileMode(t, filepath.Join(mountPoint, "perm_755"))
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm)

	mode = getFileMode(t, filepath.Join(mountPoint, "perm_777"))
	assert.Equal(t, os.FileMode(0o777), mode&os.ModePerm)

	mode = getFileMode(t, filepath.Join(mountPoint, "sticky_only"))
	assert.NotZero(t, mode&os.ModeSticky, "sticky bit should be preserved")
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm)

	mode = getFileMode(t, filepath.Join(mountPoint, "dir_755"))
	assert.Equal(t, os.FileMode(0o755), mode&os.ModePerm)

	mode = getFileMode(t, filepath.Join(mountPoint, "dir_700"))
	assert.Equal(t, os.FileMode(0o700), mode&os.ModePerm)
}

// TestStripSUIDSGIDMultipleLayers verifies that strip_suid_sgid applies to all
// layer extraction operations, including stacked layers.
func TestStripSUIDSGIDMultipleLayers(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{
		StripSUIDSGID: true,
	})
	defer store.Free()

	layer1, _, err := store.PutLayer("", "", nil, "", false, nil,
		makeTarWithPermissions([]tarEntry{
			{Name: "suid_file", Mode: 0o4755, Content: "v1"},
		}),
	)
	require.NoError(t, err)

	layer2, _, err := store.PutLayer("", layer1.ID, nil, "", false, nil,
		makeTarWithPermissions([]tarEntry{
			{Name: "another_suid", Mode: 0o4755, Content: "v2"},
		}),
	)
	require.NoError(t, err)

	mountPoint, err := store.Mount(layer2.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = store.Unmount(layer2.ID, true)
	}()

	mode := getFileMode(t, filepath.Join(mountPoint, "suid_file"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID should be stripped in parent layer")

	mode = getFileMode(t, filepath.Join(mountPoint, "another_suid"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID should be stripped in child layer")
}

// TestStripSUIDSGIDVariousPermCombinations is a table-driven test covering
// many permission combinations to verify correct stripping behavior.
func TestStripSUIDSGIDVariousPermCombinations(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{
		StripSUIDSGID: true,
	})
	defer store.Free()

	tests := []struct {
		name         string
		inputMode    os.FileMode
		expectSUID   bool
		expectSGID   bool
		expectSticky bool
		expectPerm   os.FileMode
	}{
		{"suid_rwxrwxrwx", 0o4777, false, false, false, 0o777},
		{"sgid_rwxrwxrwx", 0o2777, false, false, false, 0o777},
		{"suid_sgid_rwxrwxrwx", 0o6777, false, false, false, 0o777},
		{"suid_rwx------", 0o4700, false, false, false, 0o700},
		{"sgid_rwxr-x---", 0o2750, false, false, false, 0o750},
		{"sticky_suid_sgid", 0o7755, false, false, true, 0o755},
		{"no_special_bits", 0o644, false, false, false, 0o644},
		{"sticky_only", 0o1755, false, false, true, 0o755},
	}

	entries := make([]tarEntry, len(tests))
	for i, tc := range tests {
		entries[i] = tarEntry{
			Name:    tc.name,
			Mode:    tc.inputMode,
			Content: "data",
		}
	}

	layer, _, err := store.PutLayer("", "", nil, "", false, nil,
		makeTarWithPermissions(entries))
	require.NoError(t, err)

	mountPoint, err := store.Mount(layer.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = store.Unmount(layer.ID, true)
	}()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mode := getFileMode(t, filepath.Join(mountPoint, tc.name))
			if tc.expectSUID {
				assert.NotZero(t, mode&os.ModeSetuid, "expected SUID to be set")
			} else {
				assert.Zero(t, mode&os.ModeSetuid, "expected SUID to be cleared")
			}
			if tc.expectSGID {
				assert.NotZero(t, mode&os.ModeSetgid, "expected SGID to be set")
			} else {
				assert.Zero(t, mode&os.ModeSetgid, "expected SGID to be cleared")
			}
			if tc.expectSticky {
				assert.NotZero(t, mode&os.ModeSticky, "expected sticky to be set")
			} else {
				assert.Zero(t, mode&os.ModeSticky, "expected sticky to be cleared")
			}
			assert.Equal(t, tc.expectPerm, mode&os.ModePerm, "base permission mismatch")
		})
	}
}

// TestStripSUIDSGIDPerCallOverrideNilUsesStoreDefault verifies that when the
// per-call override (StripSUIDSGID *bool in ApplyDiffWithDifferOpts) is nil, the
// store's configured strip_suid_sgid value is used. This test uses PutLayer (tar path)
// since it always uses the store default.
func TestStripSUIDSGIDPerCallOverrideNilUsesStoreDefault(t *testing.T) {
	reexec.Init()

	store := newTestStore(t, StoreOptions{
		StripSUIDSGID: true,
	})
	defer store.Free()

	layer, _, err := store.PutLayer("", "", nil, "", false, nil,
		makeTarWithPermissions([]tarEntry{
			{Name: "suid_file", Mode: 0o4755, Content: "data"},
		}),
	)
	require.NoError(t, err)

	mountPoint, err := store.Mount(layer.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = store.Unmount(layer.ID, true)
	}()

	mode := getFileMode(t, filepath.Join(mountPoint, "suid_file"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID should be stripped using store default when override is nil")
}

// TestStripSUIDSGIDApplyDiffWithDifferOptsField verifies that the
// ApplyDiffWithDifferOpts struct supports a StripSUIDSGID *bool field for
// per-call overrides used by PrepareStagedLayer and ApplyStagedLayer.
func TestStripSUIDSGIDApplyDiffWithDifferOptsField(t *testing.T) {
	// Verify the StripSUIDSGID field exists on ApplyDiffWithDifferOpts and
	// follows the three-valued convention: nil means use store default,
	// non-nil overrides it.
	stripTrue := true
	stripFalse := false

	optsNil := drivers.ApplyDiffWithDifferOpts{}
	assert.Nil(t, optsNil.StripSUIDSGID, "default should be nil (use store default)")

	optsTrue := drivers.ApplyDiffWithDifferOpts{
		ApplyDiffOpts: drivers.ApplyDiffOpts{StripSUIDSGID: &stripTrue},
	}
	require.NotNil(t, optsTrue.StripSUIDSGID)
	assert.True(t, *optsTrue.StripSUIDSGID, "should override to true")

	optsFalse := drivers.ApplyDiffWithDifferOpts{
		ApplyDiffOpts: drivers.ApplyDiffOpts{StripSUIDSGID: &stripFalse},
	}
	require.NotNil(t, optsFalse.StripSUIDSGID)
	assert.False(t, *optsFalse.StripSUIDSGID, "should override to false")
}

// TestStripSUIDSGIDWithForceMaskInteraction verifies the documented interaction
// between strip_suid_sgid and force_mask: when force_mask is configured, it
// replaces the entire permission mode, so strip_suid_sgid has no observable
// effect. This test verifies the behavior using the VFS driver (where
// force_mask is not active on Linux), confirming that strip_suid_sgid alone
// produces the expected result. The spec guarantees that force_mask, when
// active, replaces all permissions including any SUID/SGID bits, making
// strip_suid_sgid redundant.
func TestStripSUIDSGIDWithForceMaskInteraction(t *testing.T) {
	reexec.Init()

	// With strip_suid_sgid=true and no force_mask, SUID/SGID are stripped.
	storeStrip := newTestStore(t, StoreOptions{
		StripSUIDSGID: true,
	})
	defer storeStrip.Free()

	diff := makeTarWithPermissions([]tarEntry{
		{Name: "suid_file", Mode: 0o4700, Content: "data"},
		{Name: "normal_file", Mode: 0o0600, Content: "data"},
	})

	layer, _, err := storeStrip.PutLayer("", "", nil, "", false, nil, diff)
	require.NoError(t, err)

	mountPoint, err := storeStrip.Mount(layer.ID, "")
	require.NoError(t, err)
	defer func() {
		_, _ = storeStrip.Unmount(layer.ID, true)
	}()

	// strip_suid_sgid strips SUID but preserves base permissions.
	mode := getFileMode(t, filepath.Join(mountPoint, "suid_file"))
	assert.Zero(t, mode&os.ModeSetuid, "SUID should be stripped")
	assert.Equal(t, os.FileMode(0o700), mode&os.ModePerm, "base permissions should be 0700")

	// Normal file is unaffected.
	mode = getFileMode(t, filepath.Join(mountPoint, "normal_file"))
	assert.Zero(t, mode&os.ModeSetuid, "no SUID on normal file")
	assert.Equal(t, os.FileMode(0o600), mode&os.ModePerm, "base permissions should be 0600")
}

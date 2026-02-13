# containers-storage 1 "February 2026"

## NAME
containers-storage-driver-zfs - The ZFS storage driver

## DESCRIPTION

The ZFS driver uses ZFS datasets and clones for copy-on-write semantics.

## IMPLEMENTATION

The on-disk file layout is an internal implementation detail and may change between versions. The only stable interface is the Go library API.

Requires `/dev/zfs` and the `zfs` command. Configure the parent dataset via the `zfs.fsname` option.

Layers are stored as datasets under `zfs.fsname` (e.g., `tank/containers/storage/$id`). Mountpoints are at `zfs/graph/`. All datasets use `mountpoint=legacy` so containers-storage controls mounts directly. New root layers are created with `zfs create`. Child layers are created by snapshotting the parent dataset and cloning the snapshot; the snapshot is marked for deferred deletion after cloning.

Reference: `drivers/zfs/zfs.go`

## RUNTIME

When a container needs its filesystem, the driver performs `mount(2)` with type `zfs` to mount the dataset at a path under `zfs/graph/`. Because all datasets use `mountpoint=legacy`, ZFS does not auto-mount them — the driver controls when and where each dataset is mounted. A reference counter tracks multiple users of the same mountpoint. On `Put()`, the last reference triggers an unmount.

## BUGS

https://github.com/containers/storage/issues?q=is%3Aissue+is%3Aopen+label%3Aarea%2Fzfs

## FOOTNOTES
The Containers Storage project is committed to inclusivity, a core value of open source.
The `master` and `slave` mount propagation terminology is used in this repository.
This language is problematic and divisive, and should be changed.
However, these terms are currently used within the Linux kernel and must be used as-is at this time.
When the kernel maintainers rectify this usage, Containers Storage will follow suit immediately.

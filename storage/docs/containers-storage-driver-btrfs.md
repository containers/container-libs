# containers-storage 1 "February 2026"

## NAME
containers-storage-driver-btrfs - The btrfs storage driver

## DESCRIPTION

The btrfs driver uses native btrfs copy-on-write via subvolumes and snapshots.

## IMPLEMENTATION

The on-disk file layout is an internal implementation detail and may change between versions. The only stable interface is the Go library API.

Requires a btrfs filesystem. Layers are stored as subvolumes under `btrfs/subvolumes/`. New empty layers are created as subvolumes; child layers are created as btrfs snapshots, providing true CoW semantics. Quotas are supported via btrfs qgroups. Set `btrfs.min_space` to enable quota enforcement.

Reference: `drivers/btrfs/btrfs.go`

## RUNTIME

Like VFS, there is no mount involved. Btrfs subvolumes are accessible as regular directories, so `Get()` returns the subvolume path directly. If a quota was configured, the qgroup limit is applied at this point. `Put()` is a no-op.

## BUGS

https://github.com/containers/storage/issues?q=is%3Aissue+is%3Aopen+label%3Aarea%2Fbtrfs

## FOOTNOTES
The Containers Storage project is committed to inclusivity, a core value of open source.
The `master` and `slave` mount propagation terminology is used in this repository.
This language is problematic and divisive, and should be changed.
However, these terms are currently used within the Linux kernel and must be used as-is at this time.
When the kernel maintainers rectify this usage, Containers Storage will follow suit immediately.

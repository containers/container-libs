# containers-storage 1 "February 2026"

## NAME
containers-storage-driver-vfs - The VFS storage driver

## DESCRIPTION

The VFS driver copies directories to create layers. No kernel overlay filesystem support is required.

## IMPLEMENTATION

The on-disk file layout is an internal implementation detail and may change between versions. The only stable interface is the Go library API.

Layers are stored under `vfs/dir/`. When creating a layer from a parent, the entire parent directory is copied. The copy uses reflinks (FICLONE) if supported by the filesystem, falling back to regular copying otherwise. The VFS driver works on any filesystem but is storage-inefficient without reflink support.

Reference: `drivers/vfs/driver.go`, `drivers/copy/copy_linux.go`

## RUNTIME

There is no mount involved. When a container needs its filesystem, `Get()` simply returns the layer's directory path. All layer merging happened at create time when the parent was copied, so the directory is already a complete filesystem tree. `Put()` is a no-op since there is nothing to unmount.

## BUGS

https://github.com/containers/storage/issues?q=is%3Aissue+is%3Aopen+label%3Aarea%2Fvfs

## FOOTNOTES
The Containers Storage project is committed to inclusivity, a core value of open source.
The `master` and `slave` mount propagation terminology is used in this repository.
This language is problematic and divisive, and should be changed.
However, these terms are currently used within the Linux kernel and must be used as-is at this time.
When the kernel maintainers rectify this usage, Containers Storage will follow suit immediately.

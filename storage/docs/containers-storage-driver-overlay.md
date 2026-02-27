# containers-storage 1 "February 2026"

## NAME
containers-storage-driver-overlay - The overlay storage driver

## DESCRIPTION

The overlay driver uses Linux OverlayFS for copy-on-write semantics. This is the default and recommended driver for most use cases. See [containers-storage.conf.5.md](containers-storage.conf.5.md) for configuration options.

## IMPLEMENTATION

The on-disk file layout is an internal implementation detail and may change between versions. The only stable interface is the Go library API.
The description below is intended to aid debugging and recovery, but changing content directly is not supported.

The top-level overlay directory holds layers keyed by a [chain ID](https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid) which identifies the precise sequence of parent layers leading to this one. A layer with the same DiffID can have multiple physical objects in this directory if it was created in different contexts (e.g. with or without zstd:chunked).

Each layer has at least a `diff` directory and `link` file. If there are lower layers, the layer also has a `lower` file, `merged` directory, and `work` directory. The `diff` directory has the upper layer of the overlay and is used to capture any changes to the layer. The `lower` file contains all the lower layer mounts separated by `:` and ordered from uppermost to lowermost layers. The overlay itself is mounted in the `merged` directory, and the `work` dir is needed for overlay to work.

The `link` file for each layer contains a unique string for the layer. Under the `l/` directory at the root there will be a symbolic link with that unique string pointing to the `diff` directory for the layer. The symbolic links are used to reference lower layers in the `lower` file and on mount. The links are used to shorten the total length of a layer reference without requiring changes to the layer identifier or root directory. Mounts are always done relative to root and referencing the symbolic links in order to ensure the number of lower directories can fit in a single page for making the mount syscall.

A hard upper limit of 500 lower layers is enforced.

The `overlay-layers/` directory alongside the per-layer directories contains metadata managed by the storage library. Each layer has a `${layerid}.tar-split.gz` file preserving the original tar stream structure (without file content) so that the original archive can be reconstructed exactly from the unpacked `diff/`. The directory also contains `layers.json` with global layer metadata and `layers.lock` for concurrency control.

The `overlay-containers/` directory holds running container state: `containers.json` for metadata and `containers.lock` for concurrency control.

Reference: `drivers/overlay/overlay.go`

## RUNTIME

When a container needs its filesystem, the driver performs a `mount(2)` with type `overlay`, passing the layer's `diff` directory as the upperdir and all parent layers' `diff` directories as lowerdirs. The kernel's overlayfs merges these at access time — no data is copied, and layers remain independent on disk. Writes go to the upperdir via copy-up. The mount is placed at the layer's `merged` directory, and the `work` directory is used internally by overlayfs for atomic operations like rename.

If a mount program is configured (e.g. `fuse-overlayfs` for rootless operation), it is invoked instead of the `mount(2)` syscall. When the mount option string exceeds the kernel's page size limit, the driver forks a child process that `chdir`s into the storage root and uses relative paths to shorten the options.

On `Put()`, the overlayfs mount is unmounted.

### zstd:chunked

`zstd:chunked` is a variant of the `application/vnd.oci.image.layer.v1.tar+zstd` media type that uses zstd skippable frames to include a table of contents with SHA-256 digests and offsets of individual file chunks. This allows fetching only content not already present via HTTP range requests.

Note: The zstd:chunked format is not standardized, though it is an eventual goal to do so.

Each layer has an associated big data key `chunked-manifest-cache` containing index metadata in a binary format suitable for mmap(). When pulling, existing layers are scanned for files with matching digests. Matching files are hardlinked if `use_hardlinks = "true"`, otherwise reflinked (or copied if reflinks are unsupported).

Configuration (support is enabled by default in the code):

```
[storage.options.pull_options]
enable_partial_images = "true"
```

Configuration values must be string booleans (quoted), not native TOML booleans.

Reference: `pkg/chunked/internal/compression.go`

### composefs

composefs provides an immutable filesystem layer with optional integrity verification.

Configuration:

```
[storage.options.overlay]
use_composefs = "true"
```

Configuration values must be string booleans (quoted), not native TOML booleans.

composefs requires zstd:chunked images. For non-zstd:chunked images, set `convert_images = "true"` in `[storage.options.pull_options]` to enable dynamic conversion during pulls.

With composefs enabled, the `diff/` directory becomes an object hash directory where each filename is the sha256 of its contents. Each layer has a `composefs-data/composefs.blob` file containing the composefs superblock with all metadata.

Existing layers are scanned for matching objects and reused via hardlink or reflink. An attempt is made to enable fsverity on backing files, but this is best-effort only; there is currently no support for enforced integrity verification.

Layers with or without composefs format can be mixed in the same overlay stack. Layers with a composefs blob are mounted and included in the final overlayfs stack, while layers without composefs format are reused as-is.

## BUGS

https://github.com/containers/storage/issues?q=is%3Aissue+is%3Aopen+label%3Aarea%2Foverlay

## FOOTNOTES
The Containers Storage project is committed to inclusivity, a core value of open source.
The `master` and `slave` mount propagation terminology is used in this repository.
This language is problematic and divisive, and should be changed.
However, these terms are currently used within the Linux kernel and must be used as-is at this time.
When the kernel maintainers rectify this usage, Containers Storage will follow suit immediately.

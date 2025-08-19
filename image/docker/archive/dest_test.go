package archive

import "go.podman.io/image/v5/internal/private"

var _ private.ImageDestination = (*archiveImageDestination)(nil)

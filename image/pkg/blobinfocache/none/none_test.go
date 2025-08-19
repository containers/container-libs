package none

import (
	"go.podman.io/image/v5/types"
)

var _ types.BlobInfoCache = &noCache{}

package tarball

import "go.podman.io/image/v5/internal/private"

var _ private.ImageSource = (*tarballImageSource)(nil)

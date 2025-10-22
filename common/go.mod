module go.podman.io/common

// Warning: Ensure the "go" and "toolchain" versions match exactly to prevent unwanted auto-updates

go 1.24.2

require (
	github.com/BurntSushi/toml v1.5.0
	github.com/checkpoint-restore/checkpointctl v1.4.0
	github.com/checkpoint-restore/go-criu/v7 v7.2.0
	github.com/containerd/platforms v0.2.1
	github.com/containernetworking/cni v1.3.0
	github.com/containernetworking/plugins v1.8.0
	github.com/containers/ocicrypt v1.2.1
	github.com/coreos/go-systemd/v22 v22.6.0
	github.com/cyphar/filepath-securejoin v0.4.1
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/disiqueira/gotree/v3 v3.0.2
	github.com/docker/distribution v2.8.3+incompatible
	github.com/docker/go-units v0.5.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/godbus/dbus/v5 v5.1.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/jinzhu/copier v0.4.0
	github.com/json-iterator/go v1.1.12
	github.com/moby/sys/capability v0.4.0
	github.com/onsi/ginkgo/v2 v2.27.1
	github.com/onsi/gomega v1.38.2
	github.com/opencontainers/cgroups v0.0.5
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/opencontainers/runc v1.3.2
	github.com/opencontainers/runtime-spec v1.2.1
	github.com/opencontainers/runtime-tools v0.9.1-0.20250523060157-0ea5ed0382a2
	github.com/opencontainers/selinux v1.12.0
	github.com/pkg/sftp v1.13.9
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2
	github.com/seccomp/libseccomp-golang v0.11.1
	github.com/sirupsen/logrus v1.9.3
	github.com/skeema/knownhosts v1.3.2
	github.com/spf13/cobra v1.10.1
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.11.1
	github.com/vishvananda/netlink v1.3.1
	go.etcd.io/bbolt v1.4.3
	go.podman.io/image/v5 v5.38.0
	go.podman.io/storage v1.61.0
	golang.org/x/crypto v0.43.0
	golang.org/x/sync v0.17.0
	golang.org/x/sys v0.37.0
	golang.org/x/term v0.36.0
	sigs.k8s.io/yaml v1.6.0
	tags.cncf.io/container-device-interface v1.0.1
)

require (
	dario.cat/mergo v1.0.2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/acarl005/stripansi v0.0.0-20180116102854-5a71ef0e047d // indirect
	github.com/chzyer/readline v1.5.1 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.18.0 // indirect
	github.com/containers/libtrust v0.0.0-20230121012942-c1716e8a8d01 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/docker v28.5.1+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.4 // indirect
	github.com/docker/go-connections v0.6.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-containerregistry v0.20.6 // indirect
	github.com/google/go-intervals v0.0.2 // indirect
	github.com/google/pprof v0.0.0-20250820193118-f64d9cf942d6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.1 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/letsencrypt/boulder v0.0.0-20240620165639-de9c06129bec // indirect
	github.com/manifoldco/promptui v0.9.0 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mattn/go-sqlite3 v1.14.32 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/mistifyio/go-zfs/v3 v3.1.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/proglottis/gpgme v0.1.5 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.9.1 // indirect
	github.com/sigstore/fulcio v1.7.1 // indirect
	github.com/sigstore/protobuf-specs v0.4.1 // indirect
	github.com/sigstore/sigstore v1.9.5 // indirect
	github.com/smallstep/pkcs7 v0.1.1 // indirect
	github.com/stefanberger/go-pkcs11uri v0.0.0-20230803200340-78284954bff6 // indirect
	github.com/sylabs/sif/v2 v2.22.0 // indirect
	github.com/tchap/go-patricia/v2 v2.3.3 // indirect
	github.com/titanous/rocacheck v0.0.0-20171023193734-afe73141d399 // indirect
	github.com/ulikunitz/xz v0.5.15 // indirect
	github.com/vbatts/tar-split v0.12.2 // indirect
	github.com/vbauerster/mpb/v8 v8.10.2 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.36.0 // indirect
	go.opentelemetry.io/otel/metric v1.36.0 // indirect
	go.opentelemetry.io/otel/trace v1.36.0 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/net v0.45.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	golang.org/x/tools v0.37.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250414145226-207652e42e2e // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250414145226-207652e42e2e // indirect
	google.golang.org/grpc v1.72.2 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

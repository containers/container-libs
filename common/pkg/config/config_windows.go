package config

const (
	// _configPath is the path to the containers/containers.conf
	// inside a given config directory.
	_configPath = "\\containers\\containers.conf"

	// defaultContainersConfig holds the default containers config path
	defaultContainersConfig = ""

	// DefaultSignaturePolicyPath is the default value for the
	// policy.json file.
	DefaultSignaturePolicyPath = "/etc/containers/policy.json"

	// Mount type for mounting host dir
	_typeBind = "bind"
)

var defaultHelperBinariesDir = []string{
	// FindHelperBinaries(), as a convention, interprets $BINDIR as the
	// directory where the current process binary (i.e. podman) is located.
	"$BINDIR",
}

% CONTAINERS-TLS-DETAILS.YAML 5 container-libs TLS details file format
% Miloslav Trmač
% February 2026

# NAME
containers-tls-details.yaml - syntax for the container-libs TLS details parameter file

# DESCRIPTION

The TLS details parameter file is accepted by various projects using the go.podman.io/* libraries.
There is no default location for these files; they are user-managed, and a path is provided on the CLI,
e.g. `skopeo --tls-details=`_details-file_`.yaml copy …`.

# WARNINGS

The `--tls-details` options, and this file format, should only rarely be used.
If this mechanism is not used, the software is expected to use appropriate defaults which will vary over time,
depending on version of the software, version of the Go standard library,
or platform’s configuration (e.g. `GODEBUG` values; or, not as of early 2026, but potentially, **crypto-policies**(7)).

These options _only_ affect the programs which provide the `--tls-details` option;
they do not affect other executables (e.g. **git**(1), **ssh**(1)) that may be executed internally to perform another operation.

There are some known gaps in the implementation of these options.
We hope to fix that over time, but in the meantime, careful testing feature by feature is recommended.
Known gaps include network operations performed while creating sigstore signatures (communicating with Rekor, OIDC servers, Fulcio).

# FORMAT

The TLS details files use YAML. All fields are optional.

- `minVersion`

	The minimum TLS version to use throughout the program.
	If not set, defaults to a reasonable default that may change over time.

	Users should generally not use this option and hard-code a version unless they have a process
	to ensure that the value will be kept up to date.

- `cipherSuites`

    The allowed TLS cipher suites to use throughout the program.
	The value is an array of IANA TLS Cipher Suites names.

	If not set, defaults to a reasonable default that may change over time;
    if set to an empty array, prohibits using all cipher suites.

	**Warning:** Almost no-one should ever use this option.
    Use it only if you have a bureaucracy that requires a specific list,
	and if you are confident that this bureaucracy will still exist,
    and will bring you an updated list when necessary,
	many years from now.

	**Warning:** The effectiveness of this option is limited by capabilities of the Go standard library;
	e.g., as of Go 1.25, it is not possible to change which cipher suites are used in TLS 1.3.

- `namedGroups`

	The allowed TLS named groups to use throughout the program.
	The value is an array of IANA TLS Supported Groups names.

	If not set, defaults to a reasonable default that may change over time.

	**Warning:** Almost no-one should ever use this option.
    Use it only if you have a bureaucracy that requires a specific list,
	and if you are confident that this bureaucracy will still exist,
    and will bring you an updated list when necessary,
	many years from now.

# EXAMPLE

```yaml
minVersion: "1.2"
cipherSuites:
  - "TLS_AES_128_GCM_SHA256"
  - "TLS_CHACHA20_POLY1305_SHA256"
namedGroups:
  - "secp256r1"
  - "secp384r1"
  - "x25519"
```

# SEE ALSO
buildah(1), podman(1), skopeo(1)

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.podman.io/common/pkg/libartifact/types"
)

func TestNewArtifactStorageReference(t *testing.T) {
	tests := []struct {
		name                   string
		input                  string
		expectError            bool
		errorContains          string
		errorIs                error
		expectedRefString      string
		expectedPossibleDigest string
	}{
		{
			name:              "valid OCI reference",
			input:             "quay.io/podman/machine-os:5.1",
			expectError:       false,
			expectedRefString: "quay.io/podman/machine-os:5.1",
		},
		{
			name:              "no tag adds latest",
			input:             "quay.io/machine-os/podman",
			expectError:       false,
			expectedRefString: "quay.io/machine-os/podman:latest",
		},
		{
			name:              "valid reference with full digest",
			input:             "quay.io/machine-os/podman@sha256:8b96f36deaf1d2713858eebd9ef2fee9610df8452fbd083bbfa7dca66d6fcd0b",
			expectError:       false,
			expectedRefString: "quay.io/machine-os/podman@sha256:8b96f36deaf1d2713858eebd9ef2fee9610df8452fbd083bbfa7dca66d6fcd0b",
		},
		{
			name:                   "partial digest with prefix",
			input:                  "sha256:8b96f36deaf1d2",
			expectError:            false,
			expectedPossibleDigest: "sha256:8b96f36deaf1d2",
		},
		{
			name:                   "partial digest without prefix",
			input:                  "8b96f36deaf1d2",
			expectError:            false,
			expectedPossibleDigest: "8b96f36deaf1d2",
		},
		{
			name:                   "full image ID (64-char hex)",
			input:                  "84ddb405470e733d0202d6946e48fc75a7ee231337bdeb31a8579407a7052d9e",
			expectError:            false,
			expectedPossibleDigest: "84ddb405470e733d0202d6946e48fc75a7ee231337bdeb31a8579407a7052d9e",
		},
		{
			name:                   "invalid OCI reference stored as possibleDigest",
			input:                  "invalid::reference",
			expectError:            false,
			expectedPossibleDigest: "invalid::reference",
		},
		{
			name:          "empty string error",
			input:         "",
			expectError:   true,
			errorContains: "nameOrDigest cannot be empty",
		},
		{
			name:        "tagged and digested",
			input:       "quay.io/podman/machine-os:5.1@sha256:8b96f36deaf1d2713858eebd9ef2fee9610df8452fbd083bbfa7dca66d6fcd0b",
			expectError: true,
			errorIs:     types.ErrTaggedAndDigested,
		},
		{
			name:              "localhost reference",
			input:             "localhost:5000/myimage:v1.0",
			expectError:       false,
			expectedRefString: "localhost:5000/myimage:v1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asr, err := NewArtifactStorageReference(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				if len(tt.errorContains) > 0 {
					assert.ErrorContains(t, err, tt.errorContains)
				}
				if tt.errorIs != nil {
					assert.ErrorIs(t, err, tt.errorIs)
				}
			} else {
				assert.NoError(t, err)

				// Check if we expect a valid ref or a possibleDigest
				if len(tt.expectedRefString) > 0 {
					// When we expect a ref, verify it exists and possibleDigest is empty
					assert.NotNil(t, asr.ref)
					assert.Equal(t, tt.expectedRefString, (*asr.ref).String())
					assert.Empty(t, asr.possibleDigest)
				} else if len(tt.expectedPossibleDigest) > 0 {
					// When we expect possibleDigest, verify ref is nil and possibleDigest matches
					assert.Nil(t, asr.ref)
					assert.Equal(t, tt.expectedPossibleDigest, asr.possibleDigest)
				}
			}
		})
	}
}

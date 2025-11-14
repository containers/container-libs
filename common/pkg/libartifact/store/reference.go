//go:build !remote

package store

import (
	"context"

	"go.podman.io/image/v5/docker/reference"
)

type ArtifactReference struct {
	reference.Named
}

// NewArtifactReference is a theoretical reference to an artifact.  It needs to be
// a fully qualified oci reference except for tag, where we add
// "latest" as the tag if tag is empty.  Valid references:
//
// quay.io/podman/machine-os:latest
// quay.io/podman/machine-os
// quay.io/podman/machine-os@sha256:916ede4b2b9012f91f63100f8ba82d07ed81bf8a55d23c1503285a22a9759a1e
//
// Note: Partial sha references and digests (IDs) are not allowed.
func NewArtifactReference(input string) (ArtifactReference, error) {
	ar := ArtifactReference{}
	named, err := stringToNamed(input)
	if err != nil {
		return ArtifactReference{}, err
	}
	ar.Named = named
	return ar, nil
}

func (ar ArtifactReference) IsDigested() bool {
	_, isDigested := ar.Named.(reference.Digested)
	return isDigested
}

type ArtifactStoreReference struct {
	ArtifactFromStore *Artifact
	IsDigested        bool
	Ref               reference.Named
}

// NewArtifactStorageReference refers to an object already in the artifact store.  It
// can be a name or a full or partial digest.  Conveniently, it also embeds the artifact
// as part of its return.
func NewArtifactStorageReference(nameOrDigest string, as *ArtifactStore) (ArtifactStoreReference, error) {
	lookupInput := nameOrDigest
	asf := ArtifactStoreReference{}
	al, err := as.getArtifacts(context.Background(), nil)
	if err != nil {
		return ArtifactStoreReference{}, err
	}

	// Try to parse as a valid OCI reference
	named, parseErr := stringToNamed(nameOrDigest)
	if parseErr == nil {
		lookupInput = named.String()
	}

	// Lookup in the store
	a, isDigest, err := al.getByNameOrDigest(lookupInput)
	if err != nil {
		return ArtifactStoreReference{}, err
	}

	// If parsing failed, parse the artifact's name instead
	if parseErr != nil {
		fqName, err := a.GetName()
		if err != nil {
			return ArtifactStoreReference{}, err
		}
		named, err = stringToNamed(fqName)
		if err != nil {
			return ArtifactStoreReference{}, err
		}
	}

	asf.Ref = named
	asf.IsDigested = isDigest
	asf.ArtifactFromStore = a
	return asf, nil
}

// stringToNamed converts a string to a reference.Named.
func stringToNamed(s string) (reference.Named, error) {
	named, err := reference.ParseNamed(s)
	if err != nil {
		return ArtifactReference{}, err
	}
	// If the supplied input is neither tagged nor has
	// a digest, then add "latest"
	_, isTagged := named.(reference.Tagged)
	_, isDigested := named.(reference.Digested)
	if !isTagged && !isDigested {
		named = reference.TagNameOnly(named)
	}
	return named, nil
}

package toc

import (
	"testing"
)

func TestGetTOCDigest(t *testing.T) {
	t.Run("ValidTOCDigestAnnotation", func(t *testing.T) {
		expectedDigest := "sha256:8bc94b65d0b3ae8998cc0405a424ee7c3a04c72996f99eda9670374832dc9667"
		annotations := map[string]string{
			tocJSONDigestAnnotation: expectedDigest,
		}

		digestPtr, err := GetTOCDigest(annotations)
		if err != nil {
			t.Error(err)
		}
		if digestPtr == nil {
			t.Errorf("Expected a non-nil digest pointer")
		} else if digestPtr.String() != expectedDigest {
			t.Errorf("Expected digest %s, but got %s", expectedDigest, digestPtr.String())
		}
	})

	t.Run("ValidTOCDigestAnnotation_SHA256", func(t *testing.T) {
		expectedDigest := "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
		annotations := map[string]string{
			tocJSONDigestAnnotation: expectedDigest,
		}

		digestPtr, err := GetTOCDigest(annotations)
		if err != nil {
			t.Error(err)
		}
		if digestPtr == nil {
			t.Errorf("Expected a non-nil digest pointer")
		} else if digestPtr.String() != expectedDigest {
			t.Errorf("Expected digest %s, but got %s", expectedDigest, digestPtr.String())
		}
	})

	t.Run("ValidTOCDigestAnnotation_SHA512", func(t *testing.T) {
		expectedDigest := "sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
		annotations := map[string]string{
			tocJSONDigestAnnotation: expectedDigest,
		}

		digestPtr, err := GetTOCDigest(annotations)
		if err != nil {
			t.Error(err)
		}
		if digestPtr == nil {
			t.Errorf("Expected a non-nil digest pointer")
		} else if digestPtr.String() != expectedDigest {
			t.Errorf("Expected digest %s, but got %s", expectedDigest, digestPtr.String())
		}
	})

	t.Run("InvalidTOCDigestAnnotation", func(t *testing.T) {
		annotations := map[string]string{
			tocJSONDigestAnnotation: "invalid-checksum",
		}

		_, err := GetTOCDigest(annotations)
		if err == nil {
			t.Fatal("Expected error")
		}
	})

	t.Run("InvalidTOCDigestAnnotation_SHA256", func(t *testing.T) {
		// Invalid SHA256 digest - wrong length (should be 64 hex chars after sha256:)
		invalidDigest := "sha256:invalid123"
		annotations := map[string]string{
			tocJSONDigestAnnotation: invalidDigest,
		}

		_, err := GetTOCDigest(annotations)
		if err == nil {
			t.Fatal("Expected error for invalid SHA256 digest")
		}
	})

	t.Run("InvalidTOCDigestAnnotation_SHA512", func(t *testing.T) {
		// Invalid SHA512 digest - wrong length (should be 128 hex chars after sha512:)
		invalidDigest := "sha512:invalid456"
		annotations := map[string]string{
			tocJSONDigestAnnotation: invalidDigest,
		}

		_, err := GetTOCDigest(annotations)
		if err == nil {
			t.Fatal("Expected error for invalid SHA512 digest")
		}
	})

	t.Run("NoValidAnnotations", func(t *testing.T) {
		annotations := map[string]string{}

		digestPtr, err := GetTOCDigest(annotations)
		if err != nil {
			t.Error(err)
		}
		if digestPtr != nil {
			t.Errorf("Expected nil digest pointer, but got %s", digestPtr.String())
		}
	})
}

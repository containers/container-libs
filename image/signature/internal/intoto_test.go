package internal

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseInTotoStatement(t *testing.T) {
	t.Run("valid v1 statement", func(t *testing.T) {
		data := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [
				{
					"name": "test-image",
					"digest": {
						"sha256": "634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00"
					}
				}
			],
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": {}
		}`)

		statement, err := ParseInTotoStatement(data)
		require.NoError(t, err)
		require.NotNil(t, statement)
		assert.Equal(t, "https://in-toto.io/Statement/v1", statement.Type)
		assert.Len(t, statement.Subject, 1)
		assert.Equal(t, "test-image", statement.Subject[0].Name)
		assert.Equal(t, "634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00", statement.Subject[0].Digest["sha256"])
		assert.Equal(t, "https://slsa.dev/provenance/v1", statement.PredicateType)
	})

	t.Run("valid v0.1 statement", func(t *testing.T) {
		data := []byte(`{
			"_type": "https://in-toto.io/Statement/v0.1",
			"subject": [
				{
					"name": "test-image",
					"digest": {
						"sha256": "abcd1234"
					}
				}
			],
			"predicateType": "https://example.com/predicate/v1",
			"predicate": {"key": "value"}
		}`)

		statement, err := ParseInTotoStatement(data)
		require.NoError(t, err)
		require.NotNil(t, statement)
		assert.Equal(t, "https://in-toto.io/Statement/v0.1", statement.Type)
	})

	t.Run("multiple subjects", func(t *testing.T) {
		data := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [
				{
					"name": "image1",
					"digest": {"sha256": "digest1"}
				},
				{
					"name": "image2",
					"digest": {"sha256": "digest2", "sha512": "digest2-512"}
				}
			],
			"predicateType": "https://example.com/predicate",
			"predicate": {}
		}`)

		statement, err := ParseInTotoStatement(data)
		require.NoError(t, err)
		require.NotNil(t, statement)
		assert.Len(t, statement.Subject, 2)
		assert.Equal(t, "image1", statement.Subject[0].Name)
		assert.Equal(t, "image2", statement.Subject[1].Name)
		assert.Equal(t, "digest2-512", statement.Subject[1].Digest["sha512"])
	})

	t.Run("invalid JSON", func(t *testing.T) {
		data := []byte(`not valid json`)
		_, err := ParseInTotoStatement(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing in-toto statement")
	})

	t.Run("missing _type field", func(t *testing.T) {
		data := []byte(`{
			"subject": [{"name": "test", "digest": {"sha256": "abc"}}],
			"predicateType": "https://example.com",
			"predicate": {}
		}`)

		_, err := ParseInTotoStatement(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing _type field")
	})

	t.Run("unsupported type", func(t *testing.T) {
		data := []byte(`{
			"_type": "https://example.com/UnsupportedType",
			"subject": [{"name": "test", "digest": {"sha256": "abc"}}],
			"predicateType": "https://example.com",
			"predicate": {}
		}`)

		_, err := ParseInTotoStatement(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported in-toto statement type")
	})

	t.Run("no subjects", func(t *testing.T) {
		data := []byte(`{
			"_type": "https://in-toto.io/Statement/v1",
			"subject": [],
			"predicateType": "https://example.com",
			"predicate": {}
		}`)

		_, err := ParseInTotoStatement(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has no subjects")
	})
}

func TestInTotoStatementMatchesDigest(t *testing.T) {
	statement := &InTotoStatement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []InTotoSubject{
			{
				Name: "image1",
				Digest: map[string]string{
					"sha256": "634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00",
				},
			},
			{
				Name: "image2",
				Digest: map[string]string{
					"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"sha512": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				},
			},
		},
	}

	t.Run("matches first subject sha256", func(t *testing.T) {
		d := digest.Digest("sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00")
		assert.True(t, statement.MatchesDigest(d))
	})

	t.Run("matches second subject sha256", func(t *testing.T) {
		d := digest.Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		assert.True(t, statement.MatchesDigest(d))
	})

	t.Run("matches second subject sha512", func(t *testing.T) {
		d := digest.Digest("sha512:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		assert.True(t, statement.MatchesDigest(d))
	})

	t.Run("does not match wrong digest", func(t *testing.T) {
		d := digest.Digest("sha256:0000000000000000000000000000000000000000000000000000000000000000")
		assert.False(t, statement.MatchesDigest(d))
	})

	t.Run("does not match wrong algorithm", func(t *testing.T) {
		// First subject only has sha256, not sha512
		d := digest.Digest("sha512:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00")
		assert.False(t, statement.MatchesDigest(d))
	})
}

func TestInTotoStatementMatchesDigestEmptySubjects(t *testing.T) {
	statement := &InTotoStatement{
		Type:    "https://in-toto.io/Statement/v1",
		Subject: []InTotoSubject{},
	}

	d := digest.Digest("sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00")
	assert.False(t, statement.MatchesDigest(d))
}

func TestInTotoStatementMatchesDigestEmptyDigestMap(t *testing.T) {
	statement := &InTotoStatement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []InTotoSubject{
			{
				Name:   "image-without-digest",
				Digest: map[string]string{},
			},
		},
	}

	d := digest.Digest("sha256:634a8f35b5f16dcf4aaa0822adc0b1964bb786fca12f6831de8ddc45e5986a00")
	assert.False(t, statement.MatchesDigest(d))
}

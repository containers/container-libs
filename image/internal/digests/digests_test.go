package digests

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalDefault(t *testing.T) {
	o := CanonicalDefault()
	assert.Equal(t, Options{initialized: true}, o)
}

func TestMustUse(t *testing.T) {
	o, err := MustUse(digest.SHA512)
	require.NoError(t, err)
	assert.Equal(t, Options{
		initialized: true,
		mustUse:     digest.SHA512,
	}, o)

	_, err = MustUse(digest.Algorithm("this is not a known algorithm"))
	require.Error(t, err)
}

func TestOptionsWithPreferred(t *testing.T) {
	preferSHA512, err := CanonicalDefault().WithPreferred(digest.SHA512)
	require.NoError(t, err)
	assert.Equal(t, Options{
		initialized: true,
		prefer:      digest.SHA512,
	}, preferSHA512)

	for _, c := range []struct {
		base Options
		algo digest.Algorithm
	}{
		{ // Uninitialized Options
			base: Options{},
			algo: digest.SHA256,
		},
		{ // Unavailable algorithm
			base: CanonicalDefault(),
			algo: digest.Algorithm("this is not a known algorithm"),
		},
		{ // WithPreferred already called
			base: preferSHA512,
			algo: digest.SHA512,
		},
	} {
		_, err := c.base.WithPreferred(c.algo)
		assert.Error(t, err)
	}
}

func TestOptionsWithDefault(t *testing.T) {
	defaultSHA512, err := CanonicalDefault().WithDefault(digest.SHA512)
	require.NoError(t, err)
	assert.Equal(t, Options{
		initialized: true,
		defaultAlgo: digest.SHA512,
	}, defaultSHA512)

	for _, c := range []struct {
		base Options
		algo digest.Algorithm
	}{
		{ // Uninitialized Options
			base: Options{},
			algo: digest.SHA256,
		},
		{ // Unavailable algorithm
			base: CanonicalDefault(),
			algo: digest.Algorithm("this is not a known algorithm"),
		},
		{ // WithDefault already called
			base: defaultSHA512,
			algo: digest.SHA512,
		},
	} {
		_, err := c.base.WithDefault(c.algo)
		assert.Error(t, err)
	}
}

func TestOptionsChoose(t *testing.T) {
	sha512Digest := digest.Digest("sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
	unknownDigest := digest.Digest("unknown:abcd1234")

	// The tests use sha512 = pre-existing if any; sha384 = primary configured; sha256 = supposedly irrelevant.

	mustSHA384, err := MustUse(digest.SHA384)
	require.NoError(t, err)
	mustSHA384, err = mustSHA384.WithPreferred(digest.SHA256)
	require.NoError(t, err)
	mustSHA384, err = mustSHA384.WithDefault(digest.SHA256)
	require.NoError(t, err)

	preferSHA384, err := CanonicalDefault().WithPreferred(digest.SHA384)
	require.NoError(t, err)
	preferSHA384, err = preferSHA384.WithDefault(digest.SHA256)
	require.NoError(t, err)

	defaultSHA384, err := CanonicalDefault().WithDefault(digest.SHA384)
	require.NoError(t, err)

	cases := []struct {
		opts             Options
		wantDefault      digest.Algorithm
		wantPreexisting  digest.Algorithm // Pre-existing sha512
		wantCannotChange digest.Algorithm // Pre-existing sha512, CannotChange
		wantUnavailable  digest.Algorithm // Pre-existing unavailable
	}{
		{
			opts:             Options{}, // uninitialized
			wantDefault:      "",
			wantPreexisting:  "",
			wantCannotChange: "",
			wantUnavailable:  "",
		},
		{
			opts:             mustSHA384,
			wantDefault:      digest.SHA384,
			wantPreexisting:  digest.SHA384,
			wantCannotChange: "",
			// Warning: We don’t generally _promise_ that unavailable digests are going to be silently ignored
			// in these situations (e.g. we might still try to validate them when reading inputs).
			wantUnavailable: digest.SHA384,
		},
		{
			opts:             preferSHA384,
			wantDefault:      digest.SHA384,
			wantPreexisting:  digest.SHA384,
			wantCannotChange: digest.SHA512,
			wantUnavailable:  digest.SHA384,
		},
		{
			opts:             defaultSHA384,
			wantDefault:      digest.SHA384,
			wantPreexisting:  digest.SHA512,
			wantCannotChange: digest.SHA512,
			wantUnavailable:  digest.SHA384,
		},
		{
			opts:             CanonicalDefault(),
			wantDefault:      digest.SHA256,
			wantPreexisting:  digest.SHA512,
			wantCannotChange: digest.SHA512,
			wantUnavailable:  digest.SHA256,
		},
	}
	for _, c := range cases {
		run := func(s Situation, want digest.Algorithm) {
			res, err := c.opts.Choose(s)
			if want == "" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, want, res)
			}
		}

		run(Situation{}, c.wantDefault)
		run(Situation{Preexisting: sha512Digest}, c.wantPreexisting)
		run(Situation{Preexisting: sha512Digest, CannotChangeAlgorithmReason: "test reason"}, c.wantCannotChange)
		run(Situation{Preexisting: unknownDigest}, c.wantUnavailable)

		run(Situation{Preexisting: unknownDigest, CannotChangeAlgorithmReason: "test reason"}, "")
		run(Situation{CannotChangeAlgorithmReason: "test reason"}, "") // CannotChangeAlgorithm with missing Preexisting
	}
}

func TestOptionsMustUseSet(t *testing.T) {
	mustSHA512, err := MustUse(digest.SHA512)
	require.NoError(t, err)
	prefersSHA512, err := CanonicalDefault().WithPreferred(digest.SHA512)
	require.NoError(t, err)
	defaultSHA512, err := CanonicalDefault().WithDefault(digest.SHA512)
	require.NoError(t, err)
	for _, c := range []struct {
		opts Options
		want digest.Algorithm
	}{
		{
			opts: mustSHA512,
			want: digest.SHA512,
		},
		{
			opts: prefersSHA512,
			want: "",
		},
		{
			opts: defaultSHA512,
			want: "",
		},
	} {
		assert.Equal(t, c.want, c.opts.MustUseSet())
	}
}

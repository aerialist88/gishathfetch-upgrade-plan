package tcgmarketplace

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Proves our hand-rolled EME-OAEP matches the standard: encrypt with our impl
// on a generated 2048-bit key (large enough that stdlib will decrypt it), then
// round-trip through rsa.DecryptOAEP. If the padding/MGF1/modexp were wrong,
// decryption would fail or return different bytes.
func TestEncryptOAEPRaw_RoundTripsWithStdlib(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	msg := []byte("Gishath, Sun's Avatar")
	ct, err := encryptOAEPRaw(sha1.New(), &priv.PublicKey, msg)
	require.NoError(t, err)

	pt, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, ct, nil)
	require.NoError(t, err)
	require.Equal(t, msg, pt)
}

// The ciphertext is randomized (OAEP), so we can't assert an exact URL. Instead
// we assert the structural invariants a working link must have — these catch a
// broken/rotated key, a padding change, or a path-unsafe segment.
func TestBuildSearchURL_Structure(t *testing.T) {
	pub := loadSearchPublicKey()
	require.NotNil(t, pub, "embedded public key must parse")

	got := buildSearchURL("Gishath, Sun's Avatar")

	prefix := StoreBaseURL + "/search/"
	require.True(t, strings.HasPrefix(got, prefix), "url should be a /search/ deep link, got %q", got)

	segments := strings.Split(strings.TrimPrefix(got, prefix), "/")
	require.Len(t, segments, 2, "expected <filter>/<catid>, got %q", got)

	for _, seg := range segments {
		require.NotContains(t, seg, "/", "segments must be path-safe (\"/\"->\"_\")")
		raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(seg, "_", "/"))
		require.NoError(t, err, "segment must be valid base64 after _->/ ")
		require.Len(t, raw, pub.Size(), "ciphertext must be one RSA block")
	}
}

func TestBuildSearchURL_RandomizedPerCall(t *testing.T) {
	// OAEP is non-deterministic: two links for the same card must differ, which
	// confirms we're actually encrypting rather than emitting a constant.
	require.NotEqual(t, buildSearchURL("Atraxa, Praetors' Voice"), buildSearchURL("Atraxa, Praetors' Voice"))
}

func TestBuildSearchURL_FallsBackWhenNameTooLong(t *testing.T) {
	// A 1024-bit OAEP-SHA1 block holds ~86 bytes; anything longer can't be
	// encrypted, so the link must degrade to the bare storefront, never error.
	require.Equal(t, StoreBaseURL, buildSearchURL(strings.Repeat("x", 200)))
}

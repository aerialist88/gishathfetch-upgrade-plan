package tcgmarketplace

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"hash"
	"math/big"
	"strings"
	"sync"
)

// The site's rebuilt frontend routes card searches through
// /search/<filter>/<catid>, where each segment is the plaintext
// RSA-encrypted (OAEP-SHA1) with the public key baked into its JS bundle,
// base64-encoded, then "/"->"_" so the ciphertext is path-safe (the "+" and
// "=" it may also contain are left as-is, matching the site's own links).
//
// The /product/advancedfilter API we query returns no per-listing URL, so
// previously every card linked to the bare storefront. Reproducing the
// frontend's own encryption lets us deep-link straight to the card's search
// results instead. The scheme was confirmed end-to-end against the live site:
// an OAEP-encrypted card name plus an encrypted "3" (the MTG category) loads
// that card's listings.
//
// If the store rotates this key (or changes the padding), encryption still
// succeeds locally but the link would 404/empty — buildSearchURL falls back to
// the storefront on any local error, and a rotated key would need this PEM
// refreshed from the site's current JS bundle.
const searchPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGlempQY/LwZbvzeYl76yMaH/onD
/olkEmMC5rbms3BSAA/TbzPMEVjjXcKjFHcBlKC5KOAyqNF5z7VZc6hyM6GL8l4o
bNBp6LWUmeZUWFm7rsLNXIm+Sv7IOw2z/1frbyKgWagqRstIkEnmqqsgDrLJc9OS
t5FfOO99tterVzVlAgMBAAE=
-----END PUBLIC KEY-----`

// mtgCategoryPlaintext is the category-id value the frontend encrypts into the
// second path segment for Magic: The Gathering searches (mirrors the API's
// mtgCategoryNo).
const mtgCategoryPlaintext = "3"

var (
	searchPubKeyOnce sync.Once
	searchPubKey     *rsa.PublicKey // nil if the PEM ever fails to parse
)

func loadSearchPublicKey() *rsa.PublicKey {
	searchPubKeyOnce.Do(func() {
		block, _ := pem.Decode([]byte(searchPublicKeyPEM))
		if block == nil {
			return
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return
		}
		if rsaKey, ok := parsed.(*rsa.PublicKey); ok {
			searchPubKey = rsaKey
		}
	})
	return searchPubKey
}

// encryptSegment reproduces the frontend's encryptStringWithRsaPublicKey:
// RSA-OAEP(SHA1) → standard base64 → "/"->"_" for path safety.
//
// This re-implements EME-OAEP encoding by hand instead of calling
// rsa.EncryptOAEP because the store's key is 1023-bit, which Go's stdlib now
// refuses ("keys are insecure"). The math is identical to RFC 8017 §7.1.1;
// doing it here keeps the workaround local to this store rather than flipping a
// program-wide GODEBUG=rsa1024min flag on the whole engine.
func encryptSegment(pub *rsa.PublicKey, plaintext string) (string, error) {
	ciphertext, err := encryptOAEPRaw(sha1.New(), pub, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(base64.StdEncoding.EncodeToString(ciphertext), "/", "_"), nil
}

// encryptOAEPRaw performs RSA-OAEP (MGF1 with the same hash, empty label),
// equivalent to rsa.EncryptOAEP but without the minimum-key-size guard.
func encryptOAEPRaw(h hash.Hash, pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	h.Reset()
	lHash := h.Sum(nil)
	hLen := h.Size()
	k := pub.Size()

	if len(msg) > k-2*hLen-2 {
		return nil, rsa.ErrMessageTooLong
	}

	// DB = lHash || PS(0x00…) || 0x01 || msg
	db := make([]byte, k-hLen-1)
	copy(db, lHash)
	db[len(db)-len(msg)-1] = 0x01
	copy(db[len(db)-len(msg):], msg)

	seed := make([]byte, hLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}

	mgf1XOR(db, h, seed)         // maskedDB = DB ⊕ MGF1(seed)
	mgf1XOR(seed, h, db)         // maskedSeed = seed ⊕ MGF1(maskedDB)

	// EM = 0x00 || maskedSeed || maskedDB, then c = EM^e mod n.
	em := make([]byte, k)
	copy(em[1:1+hLen], seed)
	copy(em[1+hLen:], db)

	c := new(big.Int).Exp(new(big.Int).SetBytes(em), big.NewInt(int64(pub.E)), pub.N)
	return c.FillBytes(make([]byte, k)), nil
}

// mgf1XOR XORs out with MGF1(seed) in place, matching crypto/rsa's helper.
func mgf1XOR(out []byte, h hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte
	for done := 0; done < len(out); {
		h.Reset()
		h.Write(seed)
		h.Write(counter[:])
		digest = h.Sum(digest[:0])
		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		// increment the 32-bit big-endian counter
		for i := 3; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}
}

// buildSearchURL returns a deep link to searchStr's results on the storefront,
// or the bare storefront if the link can't be built (missing/rotated key, or a
// name too long for the 1024-bit OAEP block ~86 bytes). A homepage link is the
// pre-existing behaviour, so the fallback never regresses anything.
func buildSearchURL(searchStr string) string {
	pub := loadSearchPublicKey()
	if pub == nil {
		return StoreBaseURL
	}
	filter, err := encryptSegment(pub, searchStr)
	if err != nil {
		return StoreBaseURL
	}
	catid, err := encryptSegment(pub, mtgCategoryPlaintext)
	if err != nil {
		return StoreBaseURL
	}
	return StoreBaseURL + "/search/" + filter + "/" + catid
}

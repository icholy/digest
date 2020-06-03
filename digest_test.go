package digest

import (
	"testing"

	"gotest.tools/v3/assert"
)

// I pulled this test from: https://github.com/bobziuchkovski/digest
func TestDigest(t *testing.T) {
	opt := Options{
		Method:   "GET",
		URI:      "/dir/index.html",
		Username: "Mufasa",
		Password: "Circle Of Life",
		Cnonce:   "0a4f113b",
	}
	chal := &Challenge{
		Realm:     "testrealm@host.com",
		Nonce:     "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		Algorithm: "MD5",
		Opaque:    "5ccc069c403ebaf9f0171e9517f40e41",
		QOP:       []string{"auth", "auth-int"},
	}
	cred, err := Digest(chal, opt)
	assert.NilError(t, err)
	assert.DeepEqual(t, cred, &Credentials{
		Username:  "Mufasa",
		Realm:     "testrealm@host.com",
		Nonce:     "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		URI:       "/dir/index.html",
		Response:  "6629fae49393a05397450978507c4ef1",
		Algorithm: "MD5",
		Cnonce:    "0a4f113b",
		Opaque:    "5ccc069c403ebaf9f0171e9517f40e41",
		QOP:       "auth",
		Nc:        1,
	})
}

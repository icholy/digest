package digest

import (
	"testing"

	"gotest.tools/v3/assert"
)

// https://tools.ietf.org/html/rfc7616#section-3.9
func TestDigest(t *testing.T) {
	opt := Options{
		Method:   "GET",
		URI:      "/dir/index.html",
		Username: "Mufasa",
		Password: "Circle of Life",
		Cnonce:   "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
	}
	chal := &Challenge{
		Realm:     "http-auth@example.org",
		Nonce:     "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
		Algorithm: "MD5",
		Opaque:    "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
		QOP:       []string{"auth", "auth-int"},
	}
	cred, err := Digest(chal, opt)
	assert.NilError(t, err)
	assert.DeepEqual(t, cred, &Credentials{
		Username:  "Mufasa",
		Realm:     "http-auth@example.org",
		Nonce:     "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
		URI:       "/dir/index.html",
		Response:  "8ca523f5e9506fed4657c9700eebdbec",
		Algorithm: "MD5",
		Cnonce:    "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
		Opaque:    "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
		QOP:       "auth",
		Nc:        1,
	})
}

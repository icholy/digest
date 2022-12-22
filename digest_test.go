package digest

import (
	"strconv"
	"testing"

	"gotest.tools/v3/assert"
)

// https://tools.ietf.org/html/rfc7616#section-3.9
func TestDigestMD5(t *testing.T) {
	tests := []struct {
		opt  Options
		chal *Challenge
		cred *Credentials
	}{
		{
			Options{
				Method:   "GET",
				URI:      "/dir/index.html",
				Username: "Mufasa",
				Password: "Circle of Life",
				Cnonce:   "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
			},
			&Challenge{
				Realm:     "http-auth@example.org",
				Algorithm: "MD5",
				Nonce:     "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
				Opaque:    "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
				QOP:       []string{"auth", "auth-int"},
			},
			&Credentials{
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
			},
		},
		{
			Options{
				Method:   "GET",
				URI:      "/dir/index.html",
				Username: "Mufasa",
				Password: "Circle of Life",
				Cnonce:   "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
			},
			&Challenge{
				Realm:  "http-auth@example.org",
				Nonce:  "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
				Opaque: "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
				QOP:    []string{"auth", "auth-int"},
			},
			&Credentials{
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
			},
		},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			cred, err := Digest(tt.chal, tt.opt)
			assert.NilError(t, err)
			assert.DeepEqual(t, cred, tt.cred)
		})
	}
}

func TestDigestSHA256(t *testing.T) {
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
		Algorithm: "SHA-256",
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
		Response:  "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
		Algorithm: "SHA-256",
		Cnonce:    "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
		Opaque:    "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS",
		QOP:       "auth",
		Nc:        1,
	})
}

func TestDigestUserhash(t *testing.T) {
	opt := Options{
		Method:   "GET",
		URI:      "/doe.json",
		Username: "J\u00E4s\u00F8n Doe",
		Password: "Secret, or not?",
		Cnonce:   "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v",
	}
	chal := &Challenge{
		Realm:     "api@example.org",
		Nonce:     "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
		Algorithm: "SHA-512-256",
		Opaque:    "HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS",
		QOP:       []string{"auth"},
		Charset:   "UTF-8",
		Userhash:  true,
	}
	cred, err := Digest(chal, opt)
	assert.NilError(t, err)
	assert.DeepEqual(t, cred, &Credentials{
		Username:  "793263caabb707a56211940d90411ea4a575adeccb7e360aeb624ed06ece9b0b",
		Realm:     "api@example.org",
		Nonce:     "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK",
		URI:       "/doe.json",
		Response:  "3798d4131c277846293534c3edc11bd8a5e4cdcbff78b05db9d95eeb1cec68a5",
		Algorithm: "SHA-512-256",
		Cnonce:    "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v",
		Opaque:    "HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS",
		QOP:       "auth",
		Nc:        1,
		Userhash:  true,
	})
}

func TestDigestAuthInt(t *testing.T) {
	opt := Options{
		Method:   "GET",
		URI:      "/digest-auth/auth-int/foo/bar",
		Username: "foo",
		Password: "bar",
		Cnonce:   "MjhjOWI2ZDRmNmVkNjlmYzRmMTdjZjAxYmU4ZTNkM2U=",
	}
	chal := &Challenge{
		Realm:     "me@kennethreitz.com",
		Nonce:     "7a5462bc2121c2e609e6f71c64d341c1",
		Opaque:    "5498295c3383fbb467b160f1143e51d4",
		Algorithm: "MD5",
		QOP:       []string{"auth-int"},
	}
	cred, err := Digest(chal, opt)
	assert.NilError(t, err)
	assert.DeepEqual(t, cred, &Credentials{
		Username:  "foo",
		Realm:     "me@kennethreitz.com",
		Nonce:     "7a5462bc2121c2e609e6f71c64d341c1",
		URI:       "/digest-auth/auth-int/foo/bar",
		Response:  "a86955ec413135f7902c0bae37d75469",
		Algorithm: "MD5",
		Cnonce:    "MjhjOWI2ZDRmNmVkNjlmYzRmMTdjZjAxYmU4ZTNkM2U=",
		Opaque:    "5498295c3383fbb467b160f1143e51d4",
		QOP:       "auth-int",
		Nc:        1,
	})
}

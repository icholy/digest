package digest

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Prefix for digest authentication headers
const Prefix = "Digest "

// IsDigest returns true if the header value is a digest auth header
func IsDigest(header string) bool {
	return strings.HasPrefix(header, Prefix)
}

// Options for creating a credentials
type Options struct {
	Method   string
	URI      string
	Count    int
	Username string
	Password string

	// used for testing
	Cnonce string
}

// Digest creates credentials from a challenge and request options.
// Note: if you want to re-use a challenge, you must increment the Count.
func Digest(c *Challenge, o Options) (*Credentials, error) {
	// we only support qop=auth and no qop
	if len(c.QOP) != 0 && !c.SupportsQOP("auth") {
		return nil, fmt.Errorf("digest: unsuported qop: %q", strings.Join(c.QOP, ","))
	}
	// we only support md5
	var h hash.Hash
	switch c.Algorithm {
	case "MD5":
		h = md5.New()
	case "SHA-256":
		h = sha256.New()
	case "SHA-512":
		h = sha512.New()
	default:
		return nil, fmt.Errorf("digest: unsuported algorithm: %q", c.Algorithm)
	}
	// create the a1 & a2 values as described in the rfc
	a1 := hashf(h, "%s:%s:%s", o.Username, c.Realm, o.Password)
	a2 := hashf(h, "%s:%s", o.Method, o.URI)
	// generate the response
	var qop string
	var response string
	if len(c.QOP) == 0 {
		response = hashf(h, "%s:%s:%s", a1, c.Nonce, a2)
	} else {
		qop = "auth"
		if o.Cnonce == "" {
			o.Cnonce = cnonce()
		}
		if o.Count == 0 {
			o.Count = 1
		}
		response = hashf(h, "%s:%s:%08x:%s:%s:%s", a1, c.Nonce, o.Count, o.Cnonce, qop, a2)
	}
	return &Credentials{
		Username:  o.Username,
		Realm:     c.Realm,
		Nonce:     c.Nonce,
		URI:       o.URI,
		Response:  response,
		Algorithm: c.Algorithm,
		Cnonce:    o.Cnonce,
		Opaque:    c.Opaque,
		QOP:       qop,
		Nc:        o.Count,
	}, nil
}

func hashf(h hash.Hash, format string, args ...interface{}) string {
	h.Reset()
	fmt.Fprintf(h, format, args...)
	return hex.EncodeToString(h.Sum(nil))
}

func cnonce() string {
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	return hex.EncodeToString(b)
}

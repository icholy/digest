package digest

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/icholy/digest/internal/param"
)

type Credentials struct {
	Username  string
	Realm     string
	Nonce     string
	URI       string
	Response  string
	Algorithm string
	Cnonce    string
	Opaque    string
	QOP       string
	Nc        int
}

func ParseCredentials(s string) (*Credentials, error) {
	if !IsDigest(s) {
		return nil, errors.New("digest: invalid credentials prefix")
	}
	s = s[len(Prefix):]
	pp, err := param.Parse(s)
	if err != nil {
		return nil, err
	}
	var c Credentials
	for _, p := range pp {
		switch p.Key {
		case "username":
			c.Username = p.Value
		case "realm":
			c.Realm = p.Value
		case "nonce":
			c.Nonce = p.Value
		case "uri":
			c.URI = p.Value
		case "response":
			c.Response = p.Value
		case "algorithm":
			c.Algorithm = p.Value
		case "cnonce":
			c.Cnonce = p.Value
		case "opaque":
			c.Opaque = p.Value
		case "qop":
			c.QOP = p.Value
		case "nc":
			nc, err := strconv.ParseInt(p.Value, 16, 32)
			if err != nil {
				return nil, fmt.Errorf("digest: invalid nc: %w", err)
			}
			c.Nc = int(nc)
		}
	}
	return &c, nil
}

func (c *Credentials) String() string {
	var pp []param.Param
	pp = append(pp,
		param.Param{
			Key:   "username",
			Value: c.Username,
			Quote: true,
		},
		param.Param{
			Key:   "realm",
			Value: c.Realm,
			Quote: true,
		},
		param.Param{
			Key:   "nonce",
			Value: c.Nonce,
			Quote: true,
		},
		param.Param{
			Key:   "uri",
			Value: c.URI,
			Quote: true,
		},
		param.Param{
			Key:   "response",
			Value: c.Response,
			Quote: true,
		},
	)
	if c.Algorithm != "" {
		pp = append(pp, param.Param{
			Key:   "algorithm",
			Value: c.Algorithm,
		})
	}
	if c.QOP != "" {
		pp = append(pp, param.Param{
			Key:   "cnonce",
			Value: c.Cnonce,
			Quote: true,
		})
	}
	if c.Opaque != "" {
		pp = append(pp, param.Param{
			Key:   "opque",
			Value: c.Opaque,
			Quote: true,
		})
	}
	if c.QOP != "" {
		pp = append(pp,
			param.Param{
				Key:   "qop",
				Value: c.QOP,
			},
			param.Param{
				Key:   "nc",
				Value: fmt.Sprintf("%08x", c.Nc),
			},
		)
	}
	return Prefix + param.Format(pp...)
}

package digest

import (
	"errors"
	"strings"

	"github.com/icholy/digest/internal/param"
)

// Challenge is a challange sent in the WWW-Authenticate header
type Challenge struct {
	Realm     string
	Domain    []string
	Nonce     string
	Opaque    string
	Stale     bool
	Algorithm string
	QOP       []string
}

// SupportsQOP returns true if the challenge advertises support
// for the provided qop value
func (c *Challenge) SupportsQOP(qop string) bool {
	for _, v := range c.QOP {
		if v == qop {
			return true
		}
	}
	return false
}

// ParseChallenge parses the WWW-Authenticate header challenge
func ParseChallenge(s string) (*Challenge, error) {
	if !IsDigest(s) {
		return nil, errors.New("digest: invalid challenge prefix")
	}
	s = s[len(Prefix):]
	pp, err := param.Parse(s)
	if err != nil {
		return nil, err
	}
	var c Challenge
	for _, p := range pp {
		switch p.Key {
		case "realm":
			c.Realm = p.Value
		case "domain":
			c.Domain = strings.Fields(p.Value)
		case "nonce":
			c.Nonce = p.Value
		case "algorithm":
			c.Algorithm = p.Value
		case "stale":
			c.Stale = strings.ToLower(p.Value) == "true"
		case "opaque":
			c.Opaque = p.Value
		case "qop":
			c.QOP = strings.Split(p.Value, ",")
		}
	}
	return &c, nil
}

// String returns the foramtted header value
func (c *Challenge) String() string {
	var pp []param.Param
	pp = append(pp, param.Param{
		Key:   "realm",
		Value: c.Realm,
		Quote: true,
	})
	if len(c.Domain) != 0 {
		pp = append(pp, param.Param{
			Key:   "domain",
			Value: strings.Join(c.Domain, " "),
			Quote: true,
		})
	}
	pp = append(pp, param.Param{
		Key:   "nonce",
		Value: c.Nonce,
		Quote: true,
	})
	if c.Opaque != "" {
		pp = append(pp, param.Param{
			Key:   "opaque",
			Value: c.Opaque,
			Quote: true,
		})
	}
	if c.Stale {
		pp = append(pp, param.Param{
			Key:   "stale",
			Value: "true",
		})
	}
	if c.Algorithm != "" {
		pp = append(pp, param.Param{
			Key:   "algorithm",
			Value: c.Algorithm,
		})
	}
	if len(c.QOP) != 0 {
		pp = append(pp, param.Param{
			Key:   "qop",
			Value: strings.Join(c.QOP, ","),
			Quote: true,
		})
	}
	return Prefix + param.Format(pp...)
}

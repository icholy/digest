package digest

import (
	"strconv"
	"testing"

	"gotest.tools/v3/assert"
)

func TestCredentials(t *testing.T) {
	tests := []struct {
		input       string
		credentials *Credentials
	}{
		{
			input: `Digest username="root", realm="AXIS_ACCC8EB3494E", nonce="PNHWZB6nBQA=316099a140230c2db387fc75ee1c8ae838a750d8", uri="/axis-cgi/com/ptz.cgi?camera=1&continuouspantiltmove=-49,0", response="9bbb9764c769f388f8e5ff4d26bd0449", algorithm=MD5, cnonce="17b7311e0c27a979", qop=auth, nc=00000003`,
			credentials: &Credentials{
				Username:  "root",
				Realm:     "AXIS_ACCC8EB3494E",
				Nonce:     "PNHWZB6nBQA=316099a140230c2db387fc75ee1c8ae838a750d8",
				URI:       "/axis-cgi/com/ptz.cgi?camera=1&continuouspantiltmove=-49,0",
				Response:  "9bbb9764c769f388f8e5ff4d26bd0449",
				Algorithm: "MD5",
				Cnonce:    "17b7311e0c27a979",
				QOP:       "auth",
				Nc:        3,
			},
		},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			c, err := ParseCredentials(tt.input)
			assert.NilError(t, err)
			assert.DeepEqual(t, c, tt.credentials)
			assert.DeepEqual(t, c.String(), tt.input)
		})
	}
}

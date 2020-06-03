package digest

import (
	"strconv"
	"testing"

	"gotest.tools/v3/assert"
)

func TestChallenge(t *testing.T) {
	tests := []struct {
		input     string
		challenge *Challenge
	}{
		{
			input: `Digest realm="AXIS_ACCC8EB3494E", nonce="PNHWZB6nBQA=316099a140230c2db387fc75ee1c8ae838a750d8", stale=true, algorithm=MD5, qop="auth"`,
			challenge: &Challenge{
				Realm:     "AXIS_ACCC8EB3494E",
				Nonce:     "PNHWZB6nBQA=316099a140230c2db387fc75ee1c8ae838a750d8",
				Stale:     true,
				Algorithm: "MD5",
				QOP:       []string{"auth"},
			},
		},
		{
			input: `Digest realm="AXIS_ACCC8EB3494E", nonce="PNHWZB6nBQA=316099a140230c2db387fc75ee1c8ae838a750d8", algorithm=MD5-sess, qop="auth"`,
			challenge: &Challenge{
				Realm:     "AXIS_ACCC8EB3494E",
				Nonce:     "PNHWZB6nBQA=316099a140230c2db387fc75ee1c8ae838a750d8",
				Algorithm: "MD5-sess",
				QOP:       []string{"auth"},
			},
		},
	}
	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			c, err := ParseChallenge(tt.input)
			assert.NilError(t, err)
			assert.DeepEqual(t, tt.challenge, c)
			assert.DeepEqual(t, c.String(), tt.input)
		})
	}
}

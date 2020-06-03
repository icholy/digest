package param

import (
	"strconv"
	"testing"

	"gotest.tools/v3/assert"
)

func TestParam(t *testing.T) {
	tests := []struct {
		input  string
		err    string
		params []Param
	}{
		{
			input: `key="value"`,
			params: []Param{
				{Key: "key", Value: "value", Quote: true},
			},
		},
		{
			input: `key="value", key2="value2"`,
			params: []Param{
				{Key: "key", Value: "value", Quote: true},
				{Key: "key2", Value: "value2", Quote: true},
			},
		},
		{
			input: `key=value`,
			params: []Param{
				{Key: "key", Value: "value"},
			},
		},
		{
			input: `key=value, key2="value2"`,
			params: []Param{
				{Key: "key", Value: "value"},
				{Key: "key2", Value: "value2", Quote: true},
			},
		},
		{
			input: `key=value, key="fo `,
			err:   "param: EOF",
		},
		{
			input: `username="root", realm="AXIS_ACCC8EB3494E", nonce="PNHWZB6nBQA=316099a140230c2db387fc75ee1c8ae838a750d8", uri="/axis-cgi/com/ptz.cgi?camera=1&continuouspantiltmove=-25,0", algorithm=MD5, response="f43e94d69d124e500f920fceedd3c0a7", qop=auth, nc=00000001, cnonce="7f8e0343e70d90d4"`,
			params: []Param{
				{Key: "username", Value: "root", Quote: true},
				{Key: "realm", Value: "AXIS_ACCC8EB3494E", Quote: true},
				{Key: "nonce", Value: "PNHWZB6nBQA=316099a140230c2db387fc75ee1c8ae838a750d8", Quote: true},
				{Key: "uri", Value: "/axis-cgi/com/ptz.cgi?camera=1&continuouspantiltmove=-25,0", Quote: true},
				{Key: "algorithm", Value: "MD5", Quote: false},
				{Key: "response", Value: "f43e94d69d124e500f920fceedd3c0a7", Quote: true},
				{Key: "qop", Value: "auth"},
				{Key: "nc", Value: "00000001"},
				{Key: "cnonce", Value: "7f8e0343e70d90d4", Quote: true},
			},
		},
		{
			input: `key=value-with-dashes`,
			params: []Param{
				{Key: "key", Value: "value-with-dashes"},
			},
		},
	}
	for i, tt := range tests {
		tt := tt
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Run("Parse", func(t *testing.T) {
				params, err := Parse(tt.input)
				if tt.err != "" {
					assert.Error(t, err, tt.err)
				} else {
					assert.NilError(t, err, tt.input)
					assert.DeepEqual(t, params, tt.params)
				}
			})
			t.Run("Format", func(t *testing.T) {
				if tt.err != "" {
					return
				}
				assert.Equal(t, Format(tt.params...), tt.input)
			})
		})
	}
}

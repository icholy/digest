package param

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Param is a key/value header parameter
type Param struct {
	Key   string
	Value string
	Quote bool
}

// String returns the formatted parameter
func (p Param) String() string {
	if p.Quote {
		return fmt.Sprintf("%s=%q", p.Key, p.Value)
	}
	return fmt.Sprintf("%s=%s", p.Key, p.Value)
}

// Format formats the parameters to be included in the header
func Format(pp ...Param) string {
	var b strings.Builder
	for i, p := range pp {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(p.String())
	}
	return b.String()
}

// Parse parses the header parameters
func Parse(s string) ([]Param, error) {
	var pp []Param
	r := bufio.NewReader(strings.NewReader(s))
	for i := 0; true; i++ {
		// see if there's more to read
		if _, err := r.Peek(1); err == io.EOF {
			break
		}
		// read key/value pair
		p, err := parseParam(r, i == 0)
		if err != nil {
			return nil, fmt.Errorf("param: %w", err)
		}
		pp = append(pp, p)
	}
	return pp, nil
}

func parseIdent(r *bufio.Reader) (string, error) {
	var ident []byte
	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if !(('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || '0' <= b && b <= '9' || b == '-') {
			if err := r.UnreadByte(); err != nil {
				return "", err
			}
			break
		}
		ident = append(ident, b)
	}
	return string(ident), nil
}

func parseString(r *bufio.Reader) (string, error) {
	var s []byte
	// read the open quote
	b, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	if b != '"' {
		return "", errors.New("missing open quote")
	}
	// read the string
	var escaped bool
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if escaped {
			s = append(s, b)
			escaped = false
			continue
		}
		if b == '\\' {
			escaped = true
			continue
		}
		// closing quote
		if b == '"' {
			break
		}
		s = append(s, b)
	}
	return string(s), nil
}

func skipComma(r *bufio.Reader) error {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if b != ' ' && b != ',' {
			return r.UnreadByte()
		}
	}
}

func parseParam(r *bufio.Reader, first bool) (Param, error) {
	if !first {
		if err := skipComma(r); err != nil {
			return Param{}, err
		}
	}
	// read the key
	key, err := parseIdent(r)
	if err != nil {
		return Param{}, err
	}
	// read the equals sign
	eq, err := r.ReadByte()
	if err != nil {
		return Param{}, err
	}
	if eq != '=' {
		return Param{}, fmt.Errorf("expected '=', got %c", eq)
	}
	// read the value
	var value string
	var quote bool
	if b, _ := r.Peek(1); len(b) == 1 && b[0] == '"' {
		quote = true
		value, err = parseString(r)
	} else {
		value, err = parseIdent(r)
	}
	if err != nil {
		return Param{}, err
	}
	return Param{Key: key, Value: value, Quote: quote}, nil
}

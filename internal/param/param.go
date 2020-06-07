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
	br := bufio.NewReader(strings.NewReader(s))
	for i := 0; true; i++ {
		// see if there's more to read
		if _, err := br.Peek(1); err == io.EOF {
			break
		}
		// read key/value pair
		p, err := parseParam(br, i == 0)
		if err != nil {
			return nil, fmt.Errorf("param: %w", err)
		}
		pp = append(pp, p)
	}
	return pp, nil
}

func parseIdent(br *bufio.Reader) (string, error) {
	var ident []byte
	for {
		b, err := br.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if !(('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || '0' <= b && b <= '9' || b == '-') {
			if err := br.UnreadByte(); err != nil {
				return "", err
			}
			break
		}
		ident = append(ident, b)
	}
	return string(ident), nil
}

func parseString(br *bufio.Reader) (string, error) {
	var s []rune
	// read the open quote
	b, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	if b != '"' {
		return "", errors.New("missing open quote")
	}
	// read the string
	var escaped bool
	for {
		r, _, err := br.ReadRune()
		if err != nil {
			return "", err
		}
		if escaped {
			s = append(s, r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		// closing quote
		if r == '"' {
			break
		}
		s = append(s, r)
	}
	return string(s), nil
}

func skipComma(br *bufio.Reader) error {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		if b != ' ' && b != ',' {
			return br.UnreadByte()
		}
	}
}

func parseParam(br *bufio.Reader, first bool) (Param, error) {
	if !first {
		if err := skipComma(br); err != nil {
			return Param{}, err
		}
	}
	// read the key
	key, err := parseIdent(br)
	if err != nil {
		return Param{}, err
	}
	// read the equals sign
	eq, err := br.ReadByte()
	if err != nil {
		return Param{}, err
	}
	if eq != '=' {
		return Param{}, fmt.Errorf("expected '=', got %c", eq)
	}
	// read the value
	var value string
	var quote bool
	if b, _ := br.Peek(1); len(b) == 1 && b[0] == '"' {
		quote = true
		value, err = parseString(br)
	} else {
		value, err = parseIdent(br)
	}
	if err != nil {
		return Param{}, err
	}
	return Param{Key: key, Value: value, Quote: quote}, nil
}

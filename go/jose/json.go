package jose

import (
	"fmt"
	"strconv"
	"unicode/utf8"
)

// MaxJSONDepth is the maximum nesting depth of arrays and objects.
const MaxJSONDepth = 32

// Number is a JSON number that was either a plain i64 integer or other form.
type Number struct {
	Int   *int64 // set when the lexeme was a plain integer fitting in int64
	Other string // set otherwise (keeps source text)
}

// Value is a JSON value.
type Value struct {
	Null   bool
	Bool   *bool
	Number *Number
	String *string
	Array  []Value
	Object []Member // source order; names unique
}

// Member is one object member.
type Member struct {
	Name  string
	Value Value
}

// AsStr returns the string value, if any.
func (v *Value) AsStr() (string, bool) {
	if v == nil || v.String == nil {
		return "", false
	}
	return *v.String, true
}

// AsArray returns the array, if any (including empty).
func (v *Value) AsArray() ([]Value, bool) {
	if v == nil || v.Array == nil {
		return nil, false
	}
	return v.Array, true
}

// IsObject reports whether v is a JSON object (including empty).
func (v *Value) IsObject() bool {
	return v != nil && v.Object != nil
}

// IsArray reports whether v is a JSON array (including empty).
func (v *Value) IsArray() bool {
	return v != nil && v.Array != nil
}

// AsI64 returns an integer only for Number.Int.
func (v *Value) AsI64() (int64, bool) {
	if v == nil || v.Number == nil || v.Number.Int == nil {
		return 0, false
	}
	return *v.Number.Int, true
}

// Get returns the named object member.
func (v *Value) Get(name string) *Value {
	if v == nil || v.Object == nil {
		return nil
	}
	for i := range v.Object {
		if v.Object[i].Name == name {
			return &v.Object[i].Value
		}
	}
	return nil
}

// JsonError is a parse failure.
type JsonError struct {
	Kind string
	Name string
	Index int
}

func (e *JsonError) Error() string {
	switch e.Kind {
	case "invalid_utf8":
		return "input is not valid UTF-8"
	case "unexpected_end":
		return "unexpected end of input"
	case "unexpected":
		return fmt.Sprintf("unexpected byte at offset %d", e.Index)
	case "invalid_string":
		return fmt.Sprintf("invalid string at offset %d", e.Index)
	case "trailing_data":
		return fmt.Sprintf("trailing data at offset %d", e.Index)
	case "duplicate_key":
		return fmt.Sprintf("duplicate member name %q", e.Name)
	case "too_deep":
		return fmt.Sprintf("nesting deeper than %d", MaxJSONDepth)
	default:
		return "json error"
	}
}

// Parse parses exactly one JSON value from input.
func Parse(input []byte) (Value, error) {
	if !utf8.Valid(input) {
		return Value{}, &JsonError{Kind: "invalid_utf8"}
	}
	p := parser{text: string(input)}
	p.skipWS()
	v, err := p.value(0)
	if err != nil {
		return Value{}, err
	}
	p.skipWS()
	if p.pos != len(p.text) {
		return Value{}, &JsonError{Kind: "trailing_data", Index: p.pos}
	}
	return v, nil
}

type parser struct {
	text string
	pos  int
}

func (p *parser) peek() (byte, bool) {
	if p.pos >= len(p.text) {
		return 0, false
	}
	return p.text[p.pos], true
}

func (p *parser) skipWS() {
	for {
		b, ok := p.peek()
		if !ok || (b != ' ' && b != '\t' && b != '\n' && b != '\r') {
			return
		}
		p.pos++
	}
}

func (p *parser) unexpected() error {
	if _, ok := p.peek(); !ok {
		return &JsonError{Kind: "unexpected_end"}
	}
	return &JsonError{Kind: "unexpected", Index: p.pos}
}

func (p *parser) expect(byteWanted byte) error {
	b, ok := p.peek()
	if !ok || b != byteWanted {
		return p.unexpected()
	}
	p.pos++
	return nil
}

func (p *parser) literal(word string, v Value) (Value, error) {
	if len(p.text) >= p.pos+len(word) && p.text[p.pos:p.pos+len(word)] == word {
		p.pos += len(word)
		return v, nil
	}
	matched := 0
	for matched < len(word) && p.pos+matched < len(p.text) && p.text[p.pos+matched] == word[matched] {
		matched++
	}
	p.pos += matched
	return Value{}, p.unexpected()
}

func (p *parser) value(depth int) (Value, error) {
	b, ok := p.peek()
	if !ok {
		return Value{}, p.unexpected()
	}
	switch b {
	case '{':
		return p.object(depth)
	case '[':
		return p.array(depth)
	case '"':
		s, err := p.string()
		if err != nil {
			return Value{}, err
		}
		return Value{String: &s}, nil
	case 't':
		t := true
		return p.literal("true", Value{Bool: &t})
	case 'f':
		f := false
		return p.literal("false", Value{Bool: &f})
	case 'n':
		return p.literal("null", Value{Null: true})
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return p.number()
	default:
		return Value{}, p.unexpected()
	}
}

func (p *parser) object(depth int) (Value, error) {
	if depth >= MaxJSONDepth {
		return Value{}, &JsonError{Kind: "too_deep"}
	}
	if err := p.expect('{'); err != nil {
		return Value{}, err
	}
	members := make([]Member, 0)
	seen := make(map[string]struct{})
	p.skipWS()
	if b, ok := p.peek(); ok && b == '}' {
		p.pos++
		return Value{Object: members}, nil
	}
	for {
		p.skipWS()
		if b, ok := p.peek(); !ok || b != '"' {
			return Value{}, p.unexpected()
		}
		name, err := p.string()
		if err != nil {
			return Value{}, err
		}
		p.skipWS()
		if err := p.expect(':'); err != nil {
			return Value{}, err
		}
		p.skipWS()
		val, err := p.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		if _, dup := seen[name]; dup {
			return Value{}, &JsonError{Kind: "duplicate_key", Name: name}
		}
		seen[name] = struct{}{}
		members = append(members, Member{Name: name, Value: val})
		p.skipWS()
		b, ok := p.peek()
		if !ok {
			return Value{}, p.unexpected()
		}
		switch b {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return Value{Object: members}, nil
		default:
			return Value{}, p.unexpected()
		}
	}
}

func (p *parser) array(depth int) (Value, error) {
	if depth >= MaxJSONDepth {
		return Value{}, &JsonError{Kind: "too_deep"}
	}
	if err := p.expect('['); err != nil {
		return Value{}, err
	}
	items := make([]Value, 0)
	p.skipWS()
	if b, ok := p.peek(); ok && b == ']' {
		p.pos++
		return Value{Array: items}, nil
	}
	for {
		p.skipWS()
		val, err := p.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		items = append(items, val)
		p.skipWS()
		b, ok := p.peek()
		if !ok {
			return Value{}, p.unexpected()
		}
		switch b {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return Value{Array: items}, nil
		default:
			return Value{}, p.unexpected()
		}
	}
}

func (p *parser) digits() error {
	start := p.pos
	for {
		b, ok := p.peek()
		if !ok || b < '0' || b > '9' {
			break
		}
		p.pos++
	}
	if p.pos == start {
		return p.unexpected()
	}
	return nil
}

func (p *parser) number() (Value, error) {
	start := p.pos
	if b, ok := p.peek(); ok && b == '-' {
		p.pos++
	}
	b, ok := p.peek()
	if !ok {
		return Value{}, p.unexpected()
	}
	switch {
	case b == '0':
		p.pos++
	case b >= '1' && b <= '9':
		if err := p.digits(); err != nil {
			return Value{}, err
		}
	default:
		return Value{}, p.unexpected()
	}
	integral := true
	if b, ok := p.peek(); ok && b == '.' {
		integral = false
		p.pos++
		if err := p.digits(); err != nil {
			return Value{}, err
		}
	}
	if b, ok := p.peek(); ok && (b == 'e' || b == 'E') {
		integral = false
		p.pos++
		if b, ok := p.peek(); ok && (b == '+' || b == '-') {
			p.pos++
		}
		if err := p.digits(); err != nil {
			return Value{}, err
		}
	}
	lexeme := p.text[start:p.pos]
	if integral {
		if n, err := strconv.ParseInt(lexeme, 10, 64); err == nil {
			return Value{Number: &Number{Int: &n}}, nil
		}
	}
	return Value{Number: &Number{Other: lexeme}}, nil
}

func (p *parser) hex4() (uint32, error) {
	if p.pos+4 > len(p.text) {
		return 0, &JsonError{Kind: "unexpected_end"}
	}
	var n uint32
	for i := 0; i < 4; i++ {
		b := p.text[p.pos]
		var d uint32
		switch {
		case b >= '0' && b <= '9':
			d = uint32(b - '0')
		case b >= 'a' && b <= 'f':
			d = uint32(b - 'a' + 10)
		case b >= 'A' && b <= 'F':
			d = uint32(b - 'A' + 10)
		default:
			return 0, &JsonError{Kind: "invalid_string", Index: p.pos}
		}
		n = (n << 4) | d
		p.pos++
	}
	return n, nil
}

func (p *parser) unicodeEscape() (rune, error) {
	at := p.pos
	first, err := p.hex4()
	if err != nil {
		return 0, err
	}
	var code uint32
	switch {
	case first >= 0xD800 && first <= 0xDBFF:
		if !hasPrefix(p.text[p.pos:], "\\u") {
			return 0, &JsonError{Kind: "invalid_string", Index: at}
		}
		p.pos += 2
		second, err := p.hex4()
		if err != nil {
			return 0, err
		}
		if second < 0xDC00 || second > 0xDFFF {
			return 0, &JsonError{Kind: "invalid_string", Index: at}
		}
		code = 0x10000 + ((first-0xD800)<<10) + (second - 0xDC00)
	case first >= 0xDC00 && first <= 0xDFFF:
		return 0, &JsonError{Kind: "invalid_string", Index: at}
	default:
		code = first
	}
	if code > utf8.MaxRune {
		return 0, &JsonError{Kind: "invalid_string", Index: at}
	}
	return rune(code), nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func (p *parser) string() (string, error) {
	if err := p.expect('"'); err != nil {
		return "", err
	}
	var out []byte
	run := p.pos
	for {
		b, ok := p.peek()
		if !ok {
			return "", &JsonError{Kind: "unexpected_end"}
		}
		switch b {
		case '"':
			out = append(out, p.text[run:p.pos]...)
			p.pos++
			return string(out), nil
		case '\\':
			out = append(out, p.text[run:p.pos]...)
			p.pos++
			esc, ok := p.peek()
			if !ok {
				return "", &JsonError{Kind: "unexpected_end"}
			}
			p.pos++
			switch esc {
			case '"', '\\', '/':
				out = append(out, esc)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, err := p.unicodeEscape()
				if err != nil {
					return "", err
				}
				var buf [utf8.UTFMax]byte
				n := utf8.EncodeRune(buf[:], r)
				out = append(out, buf[:n]...)
			default:
				return "", &JsonError{Kind: "invalid_string", Index: p.pos - 1}
			}
			run = p.pos
		default:
			if b <= 0x1F {
				return "", &JsonError{Kind: "invalid_string", Index: p.pos}
			}
			p.pos++
		}
	}
}

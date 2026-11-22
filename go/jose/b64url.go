package jose

import "fmt"

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// DecodeError is a strict base64url decode failure.
type DecodeError struct {
	Kind  string // "invalid_character", "invalid_length", "non_canonical"
	Index int
}

func (e *DecodeError) Error() string {
	switch e.Kind {
	case "invalid_character":
		return fmt.Sprintf("invalid base64url character at byte %d", e.Index)
	case "invalid_length":
		return "invalid base64url length"
	case "non_canonical":
		return "non-canonical base64url encoding"
	default:
		return "base64url decode error"
	}
}

// EncodedLen returns the unpadded base64url length of n bytes.
func EncodedLen(n int) int {
	switch n % 3 {
	case 0:
		return (n / 3) * 4
	case 1:
		return (n/3)*4 + 2
	default:
		return (n/3)*4 + 3
	}
}

func sextet(n uint32, shift uint) byte {
	return b64Alphabet[(n>>shift)&0x3f]
}

// Encode returns unpadded base64url encoding of input.
func Encode(input []byte) string {
	out := make([]byte, 0, EncodedLen(len(input)))
	i := 0
	for ; i+3 <= len(input); i += 3 {
		n := uint32(input[i])<<16 | uint32(input[i+1])<<8 | uint32(input[i+2])
		out = append(out, sextet(n, 18), sextet(n, 12), sextet(n, 6), sextet(n, 0))
	}
	rem := len(input) - i
	if rem == 1 {
		n := uint32(input[i]) << 16
		out = append(out, sextet(n, 18), sextet(n, 12))
	} else if rem == 2 {
		n := uint32(input[i])<<16 | uint32(input[i+1])<<8
		out = append(out, sextet(n, 18), sextet(n, 12), sextet(n, 6))
	}
	return string(out)
}

func b64Value(b byte) (byte, bool) {
	switch {
	case b >= 'A' && b <= 'Z':
		return b - 'A', true
	case b >= 'a' && b <= 'z':
		return b - 'a' + 26, true
	case b >= '0' && b <= '9':
		return b - '0' + 52, true
	case b == '-':
		return 62, true
	case b == '_':
		return 63, true
	default:
		return 0, false
	}
}

// Decode decodes strict, canonical, unpadded base64url.
func Decode(input string) ([]byte, error) {
	vals := make([]byte, 0, len(input))
	for i := 0; i < len(input); i++ {
		v, ok := b64Value(input[i])
		if !ok {
			return nil, &DecodeError{Kind: "invalid_character", Index: i}
		}
		vals = append(vals, v)
	}
	if len(vals)%4 == 1 {
		return nil, &DecodeError{Kind: "invalid_length"}
	}
	out := make([]byte, 0, len(vals)/4*3+2)
	i := 0
	for ; i+4 <= len(vals); i += 4 {
		n := uint32(vals[i])<<18 | uint32(vals[i+1])<<12 | uint32(vals[i+2])<<6 | uint32(vals[i+3])
		out = append(out, byte(n>>16), byte(n>>8), byte(n))
	}
	rem := vals[i:]
	switch len(rem) {
	case 2:
		if rem[1]&0x0f != 0 {
			return nil, &DecodeError{Kind: "non_canonical"}
		}
		out = append(out, (rem[0]<<2)|(rem[1]>>4))
	case 3:
		if rem[2]&0x03 != 0 {
			return nil, &DecodeError{Kind: "non_canonical"}
		}
		n := uint32(rem[0])<<10 | uint32(rem[1])<<4 | uint32(rem[2])>>2
		out = append(out, byte(n>>8), byte(n))
	}
	return out, nil
}

package awscall

import (
	"encoding/binary"
	"math"
	"sort"

	smithycbor "github.com/aws/smithy-go/encoding/cbor"
)

// encodeCBOR encodes the request shapes the engine sends: a map of text keys
// to text strings or lists of text strings (RFC 8949).
func encodeCBOR(value any) []byte {
	var out []byte
	var write func(any)
	header := func(major byte, n uint64) {
		switch {
		case n < 24:
			out = append(out, major<<5|byte(n))
		case n <= math.MaxUint8:
			out = append(out, major<<5|24, byte(n))
		case n <= math.MaxUint16:
			out = append(out, major<<5|25)
			out = binary.BigEndian.AppendUint16(out, uint16(n))
		case n <= math.MaxUint32:
			out = append(out, major<<5|26)
			out = binary.BigEndian.AppendUint32(out, uint32(n))
		default:
			out = append(out, major<<5|27)
			out = binary.BigEndian.AppendUint64(out, n)
		}
	}
	write = func(v any) {
		switch v := v.(type) {
		case string:
			header(3, uint64(len(v)))
			out = append(out, v...)
		case []string:
			header(4, uint64(len(v)))
			for _, s := range v {
				write(s)
			}
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			header(5, uint64(len(keys)))
			for _, key := range keys {
				write(key)
				write(v[key])
			}
		}
	}
	write(value)
	return out
}

// decodeCBOR decodes a response body with smithy's own CBOR decoder, the one
// the SDK uses, so a body reads exactly as it does for an SDK client: the
// first item counts and anything after it is ignored.
func decodeCBOR(data []byte) (any, error) {
	value, err := smithycbor.Decode(data)
	if err != nil {
		return nil, err
	}
	return fromCBOR(value), nil
}

func fromCBOR(value smithycbor.Value) any {
	switch v := value.(type) {
	case smithycbor.Map:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = fromCBOR(item)
		}
		return out
	case smithycbor.List:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = fromCBOR(item)
		}
		return out
	case smithycbor.String:
		return string(v)
	case smithycbor.Uint:
		return uint64(v)
	case smithycbor.NegInt:
		return -1 - int64(v)
	case smithycbor.Slice:
		return []byte(v)
	case *smithycbor.Tag:
		return fromCBOR(v.Value)
	case smithycbor.Tag:
		return fromCBOR(v.Value)
	case smithycbor.Bool:
		return bool(v)
	case smithycbor.Float32:
		return float64(v)
	case smithycbor.Float64:
		return float64(v)
	}
	return nil
}

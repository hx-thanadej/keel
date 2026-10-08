package cost

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/format"
)

// tagColumns are nested key/value columns read as Tags, lowest precedence
// first. Google's FOCUS export leaves Tags empty and carries labels and tags
// in x_ProjectLabels, x_Labels and x_Tags (repeated Key/Value records).
var tagColumns = []string{"x_ProjectLabels", "x_Labels", "x_Tags", "Tags"}

type kv struct {
	keys   []*string
	values []string
}

func isParquet(b []byte) bool {
	return len(b) >= 8 && string(b[:4]) == "PAR1" && string(b[len(b)-4:]) == "PAR1"
}

// parseParquet reads a FOCUS Parquet export. Each top-level leaf column is
// rendered as the text a CSV export would carry: decimals exactly, times as
// RFC 3339 UTC. Tags may be a JSON string column or nested key/value
// columns (see tagColumns), which are rebuilt into a JSON object.
func parseParquet(raw []byte) ([]Line, error) {
	f, err := parquet.OpenFile(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("parquet: %w", err)
	}
	schema := f.Schema()
	paths := schema.Columns()
	types := make([]parquet.Type, len(paths))
	top := map[string]bool{}
	for i, p := range paths {
		leaf, ok := schema.Lookup(p...)
		if !ok {
			return nil, fmt.Errorf("parquet: column %s not found", strings.Join(p, "."))
		}
		types[i] = leaf.Node.Type()
		top[p[0]] = true
	}
	if err := checkRequired(func(c string) bool { return top[c] }); err != nil {
		return nil, err
	}
	r := parquet.NewReader(f)
	defer func() { _ = r.Close() }()
	var out []Line
	buf := make([]parquet.Row, 256)
	for n := 1; ; {
		k, err := r.ReadRows(buf)
		for _, pr := range buf[:k] {
			row := map[string]string{}
			nested := map[string]*kv{}
			for _, v := range pr {
				i := v.Column()
				p := paths[i]
				s, err := text(v, types[i])
				if err != nil {
					return nil, fmt.Errorf("parquet row %d: %s: %w", n, strings.Join(p, "."), err)
				}
				if len(p) == 1 {
					row[p[0]] = s
					continue
				}
				if !slices.Contains(tagColumns, p[0]) {
					continue
				}
				t := nested[p[0]]
				if t == nil {
					t = &kv{}
					nested[p[0]] = t
				}
				// Key and value leaves pair by entry position; a null key
				// keeps its slot so later values stay on their own keys.
				switch strings.ToLower(p[len(p)-1]) {
				case "key":
					var k *string
					if !v.IsNull() {
						k = &s
					}
					t.keys = append(t.keys, k)
				case "value":
					t.values = append(t.values, s)
				}
			}
			// Nested labels become Tags; later sources win (Google: project
			// labels, then resource labels, then tags).
			if len(nested) > 0 {
				m := map[string]string{}
				for _, c := range tagColumns {
					if t := nested[c]; t != nil {
						for j, key := range t.keys {
							if key == nil {
								continue
							}
							m[*key] = ""
							if j < len(t.values) {
								m[*key] = t.values[j]
							}
						}
					}
				}
				if len(m) > 0 {
					b, _ := json.Marshal(m)
					row["Tags"] = string(b)
				}
			}
			l, err := lineFrom(row)
			if err != nil {
				return nil, fmt.Errorf("parquet row %d: %w", n, err)
			}
			out = append(out, l)
			n++
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("parquet: %w", err)
		}
	}
}

// text renders one value as CSV text, using the column's logical type.
func text(v parquet.Value, t parquet.Type) (string, error) {
	if v.IsNull() {
		return "", nil
	}
	if lt := t.LogicalType(); lt != nil {
		switch x := lt.Value.(type) {
		case *format.DecimalType:
			return decimalText(v, int(x.Scale))
		case *format.TimestampType:
			var d time.Duration
			switch x.Unit.Value.(type) {
			case *format.MilliSeconds:
				d = time.Millisecond
			case *format.MicroSeconds:
				d = time.Microsecond
			default:
				d = time.Nanosecond
			}
			return time.Unix(0, 0).Add(time.Duration(v.Int64()) * d).UTC().Format(time.RFC3339Nano), nil
		case *format.DateType:
			return time.Unix(0, 0).UTC().AddDate(0, 0, int(v.Int32())).Format("2006-01-02"), nil
		}
	}
	switch v.Kind() {
	case parquet.Boolean:
		return strconv.FormatBool(v.Boolean()), nil
	case parquet.Int32:
		return strconv.FormatInt(int64(v.Int32()), 10), nil
	case parquet.Int64:
		return strconv.FormatInt(v.Int64(), 10), nil
	case parquet.Int96:
		// Legacy timestamp: nanoseconds of day, then Julian day number.
		b := v.Bytes()
		if len(b) != 12 {
			return "", errors.New("bad INT96")
		}
		nanos := int64(binary.LittleEndian.Uint64(b[:8]))
		julian := int64(binary.LittleEndian.Uint32(b[8:]))
		const unixEpochJulian = 2440588
		return time.Unix((julian-unixEpochJulian)*86400, nanos).UTC().Format(time.RFC3339Nano), nil
	case parquet.Float:
		return strconv.FormatFloat(float64(v.Float()), 'f', -1, 32), nil
	case parquet.Double:
		return strconv.FormatFloat(v.Double(), 'f', -1, 64), nil
	default:
		return string(v.ByteArray()), nil
	}
}

// decimalText renders a DECIMAL stored as INT32, INT64 or big-endian two's
// complement bytes, exactly.
func decimalText(v parquet.Value, scale int) (string, error) {
	n := new(big.Int)
	switch v.Kind() {
	case parquet.Int32:
		n.SetInt64(int64(v.Int32()))
	case parquet.Int64:
		n.SetInt64(v.Int64())
	case parquet.ByteArray, parquet.FixedLenByteArray:
		b := v.ByteArray()
		n.SetBytes(b)
		if len(b) > 0 && b[0]&0x80 != 0 {
			n.Sub(n, new(big.Int).Lsh(big.NewInt(1), uint(len(b)*8)))
		}
	default:
		return "", fmt.Errorf("decimal stored as %s", v.Kind())
	}
	if scale <= 0 {
		return n.String(), nil
	}
	return new(big.Rat).SetFrac(n, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scale)), nil)).FloatString(scale), nil
}

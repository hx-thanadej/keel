package scans

import (
	"net/url"
	"strconv"
	"strings"
)

// Location is where a result points: a repository-relative path, and the
// line when the scanner gave one (0 otherwise).
type Location struct {
	Path string
	Line int
}

// String is the form a Finding's detail.locations holds: "path:line", or
// the path alone without a line.
func (l Location) String() string {
	if l.Line > 0 {
		return l.Path + ":" + strconv.Itoa(l.Line)
	}
	return l.Path
}

// ParseLocation reads a Location back from its String form.
func ParseLocation(s string) Location {
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		if n, err := strconv.Atoi(s[i+1:]); err == nil && n > 0 {
			return Location{Path: s[:i], Line: n}
		}
	}
	return Location{Path: s}
}

// Matches reports whether l and o are the same place: the same path, and
// the same line unless either side has none.
func (l Location) Matches(o Location) bool {
	return l.Path == o.Path && (l.Line == 0 || o.Line == 0 || l.Line == o.Line)
}

// NormalizePath makes a path repository-relative with forward slashes:
// no file:// scheme and no leading "./" or "/".
func NormalizePath(p string) string {
	p = strings.TrimPrefix(strings.ReplaceAll(p, `\`, "/"), "file://")
	for {
		switch {
		case strings.HasPrefix(p, "./"):
			p = p[2:]
		case strings.HasPrefix(p, "/"):
			p = p[1:]
		default:
			return p
		}
	}
}

// artifactPath resolves a SARIF artifact URI to a repository-relative path.
// An absolute file URI under a base the run declares (%SRCROOT% pointing at
// the checkout) loses that base; a relative URI against a relative base
// gains it.
func artifactPath(uri, baseID string, bases map[string]sarifBase) string {
	if u, err := url.PathUnescape(uri); err == nil {
		uri = u
	}
	uri = strings.ReplaceAll(uri, `\`, "/")
	if strings.HasPrefix(uri, "file://") {
		for _, b := range bases {
			root, ok := strings.CutPrefix(strings.ReplaceAll(b.URI, `\`, "/"), "file://")
			if !ok {
				continue
			}
			if !strings.HasSuffix(root, "/") {
				root += "/"
			}
			if rel, ok := strings.CutPrefix(strings.TrimPrefix(uri, "file://"), root); ok {
				return NormalizePath(rel)
			}
		}
		return NormalizePath(uri)
	}
	if b, ok := bases[baseID]; ok && b.URI != "" && !strings.Contains(b.URI, "://") {
		uri = strings.TrimSuffix(b.URI, "/") + "/" + uri
	}
	return NormalizePath(uri)
}

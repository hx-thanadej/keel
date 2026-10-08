// Package decisions indexes Decision Records (#150): MADR files under
// docs/decisions/ in every Service repository, with their status, so a
// Tenant can search decisions across Services and see when one changes.
package decisions

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// Record is one parsed Decision Record.
type Record struct {
	Path, Title, Status, Date, SupersededBy string
	Number                                  *int
}

var (
	numberRe     = regexp.MustCompile(`^(\d{1,5})-`)
	titleNumRe   = regexp.MustCompile(`^#\s+(?:ADR[- ]?)?(\d+)[.:]?\s+(.*)$`)
	supersededRe = regexp.MustCompile(`(?i)superseded by\s+\[?([^\]\)\n]+)`)
)

// Parse reads MADR 2–4 (front matter or "## Status" section) and
// Nygard-style records.
func Parse(path string, raw []byte) Record {
	r := Record{Path: path}
	name := path[strings.LastIndex(path, "/")+1:]
	if m := numberRe.FindStringSubmatch(name); m != nil {
		n, _ := strconv.Atoi(m[1])
		r.Number = &n
	}
	body := raw
	// YAML front matter (MADR 3+).
	if bytes.HasPrefix(raw, []byte("---\n")) {
		if end := bytes.Index(raw[4:], []byte("\n---")); end >= 0 {
			for _, line := range strings.Split(string(raw[4:4+end]), "\n") {
				k, v, ok := strings.Cut(line, ":")
				if !ok {
					continue
				}
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				switch strings.TrimSpace(k) {
				case "status":
					r.Status = v
				case "date":
					r.Date = v
				}
			}
			body = raw[4+end+4:]
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	inStatus := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case r.Title == "" && strings.HasPrefix(line, "# "):
			if m := titleNumRe.FindStringSubmatch(line); m != nil {
				r.Title = m[2]
				if r.Number == nil {
					n, _ := strconv.Atoi(m[1])
					r.Number = &n
				}
			} else {
				r.Title = strings.TrimPrefix(line, "# ")
			}
		case strings.EqualFold(line, "## Status"):
			inStatus = true
		case strings.HasPrefix(line, "## "):
			inStatus = false
		case inStatus && line != "" && r.Status == "":
			r.Status = line
		case r.Date == "" && strings.HasPrefix(strings.ToLower(line), "date:"):
			r.Date = strings.TrimSpace(line[5:])
		}
	}
	if m := supersededRe.FindStringSubmatch(r.Status); m != nil {
		r.SupersededBy = strings.TrimSpace(m[1])
	}
	r.Status = normalise(r.Status)
	if r.Title == "" {
		r.Title = strings.TrimSuffix(name, ".md")
	}
	return r
}

func normalise(s string) string {
	l := strings.ToLower(strings.TrimSpace(s))
	for _, known := range []string{"proposed", "accepted", "rejected", "deprecated", "superseded"} {
		if strings.HasPrefix(l, known) {
			return known
		}
	}
	if l == "" {
		return "unknown"
	}
	return l
}

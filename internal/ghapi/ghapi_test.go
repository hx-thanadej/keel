package ghapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hx-thanadej/keel/internal/ghapi"
)

func TestDoListLinkHeader(t *testing.T) {
	cases := []struct {
		name    string
		link    []string
		next    string
		wantErr bool
	}{
		{name: "quoted", link: []string{`<{base}/x?after=a>; rel="next", <{base}/x?after=z>; rel="last"`}, next: "/x?after=a"},
		{name: "unquoted", link: []string{`<{base}/x?after=a>; rel=next`}, next: "/x?after=a"},
		{name: "rel list", link: []string{`<{base}/x?after=a>; rel="next last"`}, next: "/x?after=a"},
		{name: "upper case param", link: []string{`<{base}/x?after=a>;REL="Next"`}, next: "/x?after=a"},
		{name: "quoted comma in another param", link: []string{`<{base}/x?after=p>; rel="prev"; title="a, b", <{base}/x?after=a>; rel="next"`}, next: "/x?after=a"},
		{name: "several headers", link: []string{`<{base}/x?after=p>; rel="prev"`, `<{base}/x?after=a>; rel="next"`}, next: "/x?after=a"},
		{name: "last page", link: []string{`<{base}/x?before=p>; rel="prev"`}, next: ""},
		{name: "no header", next: ""},
		{name: "missing angle brackets", link: []string{`{base}/x?after=a; rel="next"`}, wantErr: true},
		{name: "unterminated target", link: []string{`<{base}/x?after=a; rel="next"`}, wantErr: true},
		{name: "unterminated quote", link: []string{`<{base}/x?after=a>; rel="next`}, wantErr: true},
		{name: "garbage after target", link: []string{`<{base}/x?after=a> rel="next"`}, wantErr: true},
		{name: "two different next links", link: []string{`<{base}/x?after=a>; rel="next", <{base}/x?after=b>; rel="next"`}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, l := range c.link {
					w.Header().Add("Link", strings.ReplaceAll(l, "{base}", srv.URL))
				}
				_, _ = w.Write([]byte(`[]`))
			}))
			defer srv.Close()
			var out []any
			next, err := ghapi.Client{BaseURL: srv.URL}.DoList(context.Background(), "/x", &out)
			if c.wantErr {
				if err == nil {
					t.Fatalf("malformed Link %q: next %q, want an error", c.link, next)
				}
				return
			}
			if err != nil || next != c.next {
				t.Fatalf("next %q, %v; want %q", next, err, c.next)
			}
		})
	}
}

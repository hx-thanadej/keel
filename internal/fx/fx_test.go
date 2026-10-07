package fx_test

import (
	"os"
	"testing"

	"github.com/hx-thanadej/keel/internal/fx"
)

func TestParseECB(t *testing.T) {
	f, err := os.Open("testdata/eurofxref-daily.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	rates, err := fx.ParseECB(f)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rates {
		got[r.Currency] = r.PerEUR
		if r.Day.Format("2006-01-02") != "2026-10-06" {
			t.Errorf("day %s", r.Day)
		}
	}
	if got["USD"] != "1.1269" || got["THB"] != "37.836" || got["EUR"] != "1" {
		t.Errorf("rates %v", got)
	}
}

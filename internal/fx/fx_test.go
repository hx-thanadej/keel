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

func TestFilter(t *testing.T) {
	f, _ := os.Open("testdata/eurofxref-daily.xml")
	defer func() { _ = f.Close() }()
	rates, _ := fx.ParseECB(f)
	kept := fx.Filter(rates, rates[0].Day)
	for _, r := range kept {
		if !fx.Kept[r.Currency] {
			t.Errorf("kept %s", r.Currency)
		}
	}
	if len(kept) != 4 { // EUR, USD, THB, CNY
		t.Errorf("kept %d rates", len(kept))
	}
	if len(fx.Filter(rates, rates[0].Day.AddDate(0, 0, 1))) != 0 {
		t.Error("since must exclude older days")
	}
}

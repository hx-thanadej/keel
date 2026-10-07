package discovery_test

import (
	"testing"

	"github.com/hx-thanadej/keel/internal/discovery"
)

func TestSuggest(t *testing.T) {
	cases := map[string]*discovery.Suggestion{
		"tat-crm-prod":   {ProjectSlug: "tat-crm", Environment: "prod"},
		"tat-crm-dev":    {ProjectSlug: "tat-crm", Environment: "dev"},
		"TAT_CRM_UAT":    {ProjectSlug: "tat-crm", Environment: "uat"},
		"shared-tooling": nil,
		"prod":           nil,
		"billing-":       nil,
	}
	for name, want := range cases {
		got := discovery.Suggest(name)
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("Suggest(%q) = %+v, want %+v", name, got, want)
		}
	}
}

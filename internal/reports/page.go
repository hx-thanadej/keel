package reports

import (
	"html/template"
	"sort"
)

// The page is self-contained (no external assets) so a downloaded copy
// renders offline and can be attached to a board pack as is.
var pageTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"pct": func(p *float64) string {
		if p == nil {
			return "–"
		}
		return fmtFloat(*p*100, 0) + "%"
	},
	"num": func(p *float64) string {
		if p == nil {
			return "–"
		}
		return fmtFloat(*p, 1)
	},
	"f1":       func(v float64) string { return fmtFloat(v, 2) },
	"severity": severities,
	"over":     func(s string) bool { return len(s) > 0 && s[0] != '-' && s != "0.00" },
}).Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.TenantName}} · Keel report {{.Period}}</title>
<style>
body{font:14px/1.5 system-ui,sans-serif;color:#1d2330;background:#fff;max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0}h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid #e3e6ec;padding-bottom:4px}
.sub{color:#5b6475}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:4px 8px;border-bottom:1px solid #eef0f4}td.n,th.n{text-align:right}
.over{color:#b42318}.tiles{display:flex;flex-wrap:wrap;gap:12px}.tile{border:1px solid #e3e6ec;border-radius:6px;padding:8px 12px;min-width:120px}
.tile b{display:block;font-size:18px}.note{color:#5b6475;font-size:12px}
</style></head><body>
<h1>{{.TenantName}} — monthly report {{.Period}}</h1>
<p class="sub">Generated {{.GeneratedAt.Format "2006-01-02 15:04 UTC"}} by Keel from this Tenant's own data. Amounts in each Budget's currency.</p>

<h2>Spend against budget</h2>
{{if .Budgets}}<table><tr><th>Project</th><th>Budget</th><th class="n">Month budget</th><th class="n">Month actual</th><th class="n">Variance</th><th class="n">Year to date</th><th class="n">Year budget</th><th class="n">Year-end forecast</th></tr>
{{range .Budgets}}<tr><td>{{.Project}}</td><td>{{.Budget}}{{if not .Final}} <span class="note">(provisional)</span>{{end}}{{if .MissingFX}} <span class="note">(FX missing)</span>{{end}}</td>
<td class="n">{{.MonthBudget}} {{.Currency}}</td><td class="n">{{.MonthActual}}</td><td class="n{{if over .MonthVariance}} over{{end}}">{{.MonthVariance}}</td>
<td class="n">{{.YearToDate}}</td><td class="n">{{.YearBudget}}</td><td class="n">{{if .Forecast}}{{.Forecast}}{{else}}<span class="note">not enough history</span>{{end}}</td></tr>
{{end}}</table>{{else}}<p class="note">No Budgets for this year.</p>{{end}}

<h2>Savings</h2>
<div class="tiles"><div class="tile">Realised / month<b>{{.Savings.Realised}} {{.Savings.Currency}}</b></div>
<div class="tile">Applied / month<b>{{.Savings.Applied}} {{.Savings.Currency}}</b></div>
<div class="tile">Regressions<b>{{.Savings.Regressions}}</b></div></div>
{{if .Savings.Top}}<table><tr><th>Resource</th><th>Action</th><th class="n">Realised / month</th><th>Applied</th></tr>
{{range .Savings.Top}}<tr><td>{{.ResourceID}}</td><td>{{.Action}}</td><td class="n">{{.Realised}}</td><td>{{.AppliedAt.Format "2006-01-02"}}</td></tr>{{end}}</table>{{end}}

<h2>Delivery (DORA, production)</h2>
<div class="tiles"><div class="tile">Deployments<b>{{.DORA.Deployments}}</b></div>
<div class="tile">Per day<b>{{f1 .DORA.PerDay}}</b></div>
<div class="tile">Lead time (h)<b>{{num .DORA.LeadTimeHours}}</b></div>
<div class="tile">Change fail rate<b>{{pct .DORA.ChangeFailRate}}</b></div>
<div class="tile">Recovery (h)<b>{{num .DORA.RecoveryHours}}</b></div>
<div class="tile">Rework rate<b>{{pct .DORA.ReworkRate}}</b></div></div>
{{if .Services}}<table><tr><th>Service</th><th class="n">Deployments</th><th class="n">Lead time (h)</th><th class="n">Change fail rate</th></tr>
{{range .Services}}<tr><td>{{.Scope}}</td><td class="n">{{.Deployments}}</td><td class="n">{{num .LeadTimeHours}}</td><td class="n">{{pct .ChangeFailRate}}</td></tr>{{end}}</table>{{end}}

<h2>Security findings</h2>
<div class="tiles">{{range severity .Findings.OpenBySeverity}}<div class="tile">Open {{.Name}}<b>{{.Count}}</b></div>{{end}}
<div class="tile">Overdue<b{{if .Findings.Overdue}} class="over"{{end}}>{{.Findings.Overdue}}</b></div></div>
<p>{{.Findings.Raised}} raised and {{.Findings.Resolved}} resolved this month, {{.Findings.WithinSLA}} of them within SLA.</p>

<h2>Exceptions and access</h2>
<p>{{.Exceptions.Active}} Exceptions were in force during the month ({{.Exceptions.Granted}} newly granted); {{.Exceptions.Expiring}} expire in the next 30 days.</p>
<p>{{.Access.Requested}} access grants were requested{{if .Access.ByState}} ({{range $k, $v := .Access.ByState}}{{$k}}: {{$v}} {{end}}){{end}}, totalling {{.Access.Hours}} granted hours.</p>
</body></html>
`))

type sevCount struct {
	Name  string
	Count int
}

// severities orders counts most severe first, with unknown levels last.
func severities(m map[string]int) []sevCount {
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	out := make([]sevCount, 0, len(m))
	for k, v := range m {
		out = append(out, sevCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		ri, ok := rank[out[i].Name]
		if !ok {
			ri = 9
		}
		rj, ok := rank[out[j].Name]
		if !ok {
			rj = 9
		}
		if ri != rj {
			return ri < rj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

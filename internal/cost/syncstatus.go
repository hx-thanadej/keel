package cost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/hx-thanadej/keel/internal/activity"
	"github.com/hx-thanadej/keel/internal/store"
)

// MonthState is a billing month's outcome in its latest sync run.
type MonthState string

const (
	MonthLoaded    MonthState = "loaded"    // a new load made it current
	MonthUnchanged MonthState = "unchanged" // the pull matched the current load
	MonthEmpty     MonthState = "empty"     // the provider returned no lines
	MonthBlocked   MonthState = "blocked"   // Keel refused to load it; Reason says why
	MonthFailed    MonthState = "failed"    // the pull or load errored; Reason is the error class
)

// RunState is a payer's sync outcome as a whole: what stopped its latest
// run before it reached a month, else the worst of its months' latest
// outcomes, including months that run did not need to revisit.
type RunState string

const (
	RunOK      RunState = "ok"
	RunEmpty   RunState = "empty"
	RunBlocked RunState = "blocked"
	RunFailed  RunState = "failed"
)

var runRank = map[RunState]int{RunOK: 0, RunEmpty: 1, RunBlocked: 2, RunFailed: 3}

func (s MonthState) run() RunState {
	switch s {
	case MonthEmpty:
		return RunEmpty
	case MonthBlocked:
		return RunBlocked
	case MonthFailed:
		return RunFailed
	}
	return RunOK
}

// Reasons are codes the portal turns into words. They never carry a
// provider's message, which can quote credentials.
const (
	ReasonCurrencyUnknown  = "currency_unknown"  // month blocked: the bill's currency is unreadable
	ReasonFilesOverlap     = "files_overlap"     // month blocked: two files charge the same interval
	ReasonNoBillFiles      = "no_bill_files"     // run empty: the bucket holds no bill files
	ReasonNoBucket         = "no_bucket"         // run blocked: no bucket is recorded for the client payer
	ReasonBucketUnreadable = "bucket_unreadable" // run blocked: role assumed, bucket not readable
	ReasonRoleUnusable     = "role_unusable"     // run blocked: the client's read-only role cannot be assumed
	ReasonKeelIdentity     = "keel_identity"     // run blocked: Keel's own identity is unusable
)

// SyncMonth is one billing month's latest outcome.
type SyncMonth struct {
	Month     string     `json:"month"` // YYYY-MM
	State     MonthState `json:"state"`
	Lines     int        `json:"lines"`
	Total     string     `json:"total,omitempty"` // billed, for loaded and unchanged months
	Currency  string     `json:"currency,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Code      string     `json:"code,omitempty"` // the provider's error code, when it gave one
	Since     time.Time  `json:"since"`          // when the month entered State
	CheckedAt time.Time  `json:"checked_at"`
}

// SyncStatus is a payer's latest bill sync.
type SyncStatus struct {
	Provider         string      `json:"provider"`
	BillingAccountID string      `json:"billing_account_id"`
	Source           string      `json:"source"` // api or files
	CheckedAt        time.Time   `json:"checked_at"`
	State            RunState    `json:"state"`
	Reason           string      `json:"reason,omitempty"`
	Code             string      `json:"code,omitempty"`
	Since            time.Time   `json:"since"`
	Months           []SyncMonth `json:"months"` // newest first
}

// keptMonths bounds the months a status remembers.
const keptMonths = 6

// syncRun is what one run learned. State, Reason and Code are set only when
// something stopped the run before or beside its months.
type syncRun struct {
	tenant, provider, account, source string
	at                                time.Time
	state                             RunState
	reason, code                      string
	months                            []SyncMonth
}

// failRun marks the run failed by err, keeping only err's class and code.
func (r *syncRun) failRun(err error) {
	r.state = RunFailed
	r.reason, r.code = errorClass(err)
}

func (r *syncRun) month(m SyncMonth) {
	r.months = append(r.months, m)
}

func failedMonth(month string, err error) SyncMonth {
	class, code := errorClass(err)
	return SyncMonth{Month: month, State: MonthFailed, Reason: class, Code: code}
}

// mergeSync folds a run into the previous status. Months the run did not
// visit keep their last outcome. changed reports whether the payer's
// outcome moved: loaded and unchanged count as the same outcome, so a
// month that keeps loading new lines every hour is not a change.
func mergeSync(prev *SyncStatus, r syncRun) (next SyncStatus, changed bool) {
	next = SyncStatus{Provider: r.provider, BillingAccountID: r.account, Source: r.source, CheckedAt: r.at, Since: r.at}
	months := map[string]SyncMonth{}
	if prev != nil {
		for _, m := range prev.Months {
			months[m.Month] = m
		}
	}
	changed = prev == nil
	for _, m := range r.months {
		m.CheckedAt, m.Since = r.at, r.at
		old, seen := months[m.Month]
		if seen && sameOutcome(old.State, m.State) && old.Reason == m.Reason {
			m.Since = old.Since
		} else {
			changed = true
		}
		if m.State == MonthUnchanged && m.Lines == 0 && seen {
			m.Lines, m.Total, m.Currency = old.Lines, old.Total, old.Currency
		}
		months[m.Month] = m
	}
	for _, m := range months {
		next.Months = append(next.Months, m)
	}
	slices.SortFunc(next.Months, func(a, b SyncMonth) int { return strings.Compare(b.Month, a.Month) })
	if len(next.Months) > keptMonths {
		next.Months = next.Months[:keptMonths]
	}
	next.State, next.Reason, next.Code = RunOK, "", ""
	if r.state != "" {
		next.State, next.Reason, next.Code = r.state, r.reason, r.code
	} else {
		for _, m := range next.Months {
			if runRank[m.State.run()] > runRank[next.State] {
				next.State = m.State.run()
			}
		}
	}
	if prev != nil && prev.State == next.State && prev.Reason == next.Reason {
		next.Since = prev.Since
	} else if prev != nil {
		changed = true
	}
	return next, changed
}

func sameOutcome(a, b MonthState) bool {
	healthy := func(s MonthState) bool { return s == MonthLoaded || s == MonthUnchanged }
	return a == b || healthy(a) && healthy(b)
}

// recordSync saves a run's outcome and, when it changed, one Activity that
// says what changed in plain words.
func recordSync(ctx context.Context, st *store.Store, r syncRun) error {
	return st.InTenant(ctx, r.tenant, func(tx pgx.Tx) error {
		var prev *SyncStatus
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT to_jsonb(s) - 'tenant_id' FROM bill_sync_status s WHERE provider = $1 AND billing_account_id = $2 FOR UPDATE`,
			r.provider, r.account).Scan(&raw)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		default:
			if prev, err = decodeStatus(raw); err != nil {
				return err
			}
		}
		next, changed := mergeSync(prev, r)
		months := map[string]SyncMonth{}
		for _, m := range next.Months {
			months[m.Month] = m
		}
		mj, err := json.Marshal(months)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO bill_sync_status (tenant_id, provider, billing_account_id, source, checked_at, state, reason, code, since, months)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (tenant_id, provider, billing_account_id) DO UPDATE SET source = excluded.source, checked_at = excluded.checked_at,
				state = excluded.state, reason = excluded.reason, code = excluded.code, since = excluded.since, months = excluded.months`,
			r.tenant, r.provider, r.account, next.Source, next.CheckedAt, next.State, next.Reason, next.Code, next.Since, mj); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		outcome := activity.Success
		if next.State == RunBlocked || next.State == RunFailed {
			outcome = activity.Failure
		}
		_, err = activity.Record(ctx, tx, activity.Activity{TenantID: r.tenant, Source: "keel/cost", Type: "keel.cost.bill_sync_changed",
			Subject: "bill_sync/" + r.provider + "/" + r.account, Operation: "SyncBills", Kind: activity.Read, Actor: actor,
			Outcome: outcome, StatusDetail: describeSync(next, r), Time: r.at})
		return err
	})
}

func decodeStatus(raw []byte) (*SyncStatus, error) {
	var row struct {
		SyncStatus
		Months map[string]SyncMonth `json:"months"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	s := row.SyncStatus
	for _, m := range row.Months {
		s.Months = append(s.Months, m)
	}
	slices.SortFunc(s.Months, func(a, b SyncMonth) int { return strings.Compare(b.Month, a.Month) })
	return &s, nil
}

// describeSync is the Activity's detail: the payer and, for this run, each
// month's outcome, worded for people.
func describeSync(s SyncStatus, r syncRun) string {
	parts := []string{fmt.Sprintf("%s payer %s", s.Provider, s.BillingAccountID)}
	if r.state != "" {
		parts = append(parts, runWords[r.reason])
		if r.state == RunFailed {
			parts[len(parts)-1] = classWords[r.reason]
		}
	}
	for _, m := range r.months {
		name := m.Month
		if t, err := time.Parse("2006-01", m.Month); err == nil {
			name = t.Format("January 2006")
		}
		var what string
		switch m.State {
		case MonthLoaded, MonthUnchanged:
			what = fmt.Sprintf("%d lines loaded", m.Lines)
			if m.Total != "" {
				what += fmt.Sprintf(" (%s %s)", m.Total, m.Currency)
			}
		case MonthEmpty:
			what = "no costs found"
		case MonthBlocked:
			what = runWords[m.Reason]
		case MonthFailed:
			what = classWords[m.Reason]
		}
		parts = append(parts, name+": "+what)
	}
	return strings.Join(parts, "; ")
}

var runWords = map[string]string{
	ReasonCurrencyUnknown:  "not loaded, the bill's currency could not be read",
	ReasonFilesOverlap:     "not loaded, two bill files charge the same time",
	ReasonNoBillFiles:      "no bill files in the bucket",
	ReasonNoBucket:         "no bill bucket recorded",
	ReasonBucketUnreadable: "the bill bucket could not be read",
	ReasonRoleUnusable:     "the payer's read-only role could not be assumed",
	ReasonKeelIdentity:     "Keel's own cloud identity is unusable",
}

var classWords = map[string]string{
	"timeout":      "the billing service took too long to answer",
	"network":      "the billing service could not be reached",
	"denied":       "the billing service refused Keel's access",
	"rate_limited": "the billing service asked Keel to slow down",
	"provider":     "the billing service returned an error",
	"internal":     "Keel hit an internal error",
}

var codeShape = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{0,79}$`)

// errorClass sorts an error into a class the portal can explain, and keeps
// the provider's error code when it has one. The message is dropped.
func errorClass(err error) (class, code string) {
	var coded interface{ GetCode() string }
	if errors.As(err, &coded) && codeShape.MatchString(coded.GetCode()) {
		code = coded.GetCode()
	}
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", code
	case strings.HasPrefix(code, "AuthFailure") || strings.HasPrefix(code, "UnauthorizedOperation") || strings.HasPrefix(code, "AccessDenied"):
		return "denied", code
	case strings.HasPrefix(code, "RequestLimitExceeded"):
		return "rate_limited", code
	case code != "":
		return "provider", code
	case errors.As(err, &ne):
		if ne.Timeout() {
			return "timeout", ""
		}
		return "network", ""
	}
	return "internal", ""
}

// BillSync returns the Tenant's payers' latest bill sync, newest run first.
func (q Queries) BillSync(ctx context.Context, tenantID string) ([]SyncStatus, error) {
	out := []SyncStatus{}
	err := q.Store.InTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT to_jsonb(s) - 'tenant_id' FROM bill_sync_status s ORDER BY checked_at DESC, provider, billing_account_id`)
		if err != nil {
			return err
		}
		raws, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
		if err != nil {
			return err
		}
		for _, raw := range raws {
			s, err := decodeStatus(raw)
			if err != nil {
				return err
			}
			out = append(out, *s)
		}
		return nil
	})
	return out, err
}

// loadedMonth reads a new load's size and total for its month's status.
func loadedMonth(ctx context.Context, st *store.Store, home, loadID, month string) (SyncMonth, error) {
	m := SyncMonth{Month: month, State: MonthLoaded}
	err := st.InTenant(ctx, home, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT line_count, to_char(total_billed, 'FM999999999990.00'), currency FROM cost_loads WHERE id = $1`, loadID).Scan(&m.Lines, &m.Total, &m.Currency)
	})
	return m, err
}

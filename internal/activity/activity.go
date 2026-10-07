// Package activity records Activities in the Activity Log (ADR-0005).
//
// Record writes inside the caller's transaction, so a state change and the
// Activity describing it commit or roll back together.
package activity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Kind is the OCSF API Activity activity_id.
type Kind int

// OCSF API Activity activity_id values.
const (
	Create Kind = 1
	Read   Kind = 2
	Update Kind = 3
	Delete Kind = 4
	Other  Kind = 99
)

// Outcome is the OCSF status_id.
type Outcome int

// OCSF status_id values.
const (
	Success Outcome = 1
	Failure Outcome = 2
)

// Actor types (CONTEXT.md: humans, Pipelines and the platform itself produce Activities).
const (
	ActorHuman    = "human"
	ActorPipeline = "pipeline"
	ActorWorkload = "workload"
	ActorKeel     = "keel"
)

// OCSFVersion is the OCSF schema version the payload follows.
const OCSFVersion = "1.9.0"

// Actor is who did it.
type Actor struct {
	Type    string   `json:"type"`
	UID     string   `json:"uid"`
	Session *Session `json:"session,omitempty"`
}

// Session carries how the actor was authenticated.
type Session struct {
	Issuer  string `json:"issuer,omitempty"`
	MFA     bool   `json:"mfa,omitempty"`
	GrantID string `json:"grant_id,omitempty"`
}

// Resource is what was acted on.
type Resource struct {
	Type      string `json:"type"`
	UID       string `json:"uid"`
	OwnerTeam string `json:"owner_team,omitempty"`
}

// Why is the justification. Not a first-class OCSF field; carried as an extension.
type Why struct {
	PR     string `json:"pr,omitempty"`
	Ticket string `json:"ticket,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Activity is one entry to record.
type Activity struct {
	TenantID     string
	Source       string // producing module or adapter, e.g. "keel/catalog"
	Type         string // e.g. "keel.project.created"
	Subject      string
	Operation    string // API operation, e.g. "CreateProject"
	Kind         Kind
	Actor        Actor
	Resources    []Resource
	Why          Why
	Outcome      Outcome
	StatusDetail string // e.g. policy decision and reason
	Time         time.Time
}

var validActor = map[string]bool{ActorHuman: true, ActorPipeline: true, ActorWorkload: true, ActorKeel: true}

// Validate reports the first missing or invalid field.
func (a Activity) Validate() error {
	switch {
	case a.TenantID == "":
		return errors.New("activity: tenant id required")
	case a.Source == "":
		return errors.New("activity: source required")
	case a.Type == "":
		return errors.New("activity: type required")
	case a.Operation == "":
		return errors.New("activity: operation required")
	case a.Actor.UID == "":
		return errors.New("activity: actor uid required")
	case !validActor[a.Actor.Type]:
		return fmt.Errorf("activity: actor type %q invalid", a.Actor.Type)
	case a.Kind == 0:
		return errors.New("activity: kind required")
	case a.Outcome != Success && a.Outcome != Failure:
		return errors.New("activity: outcome required")
	}
	return nil
}

type ocsf struct {
	ClassUID     int        `json:"class_uid"`
	CategoryUID  int        `json:"category_uid"`
	ActivityID   int        `json:"activity_id"`
	TypeUID      int        `json:"type_uid"`
	SeverityID   int        `json:"severity_id"`
	StatusID     int        `json:"status_id"`
	StatusDetail string     `json:"status_detail,omitempty"`
	Time         int64      `json:"time"`
	TenantID     string     `json:"tenant_id"`
	Actor        Actor      `json:"actor"`
	API          api        `json:"api"`
	Resources    []Resource `json:"resources,omitempty"`
	Why          *Why       `json:"why,omitempty"`
	Metadata     metadata   `json:"metadata"`
}

type api struct {
	Operation string `json:"operation"`
}

type metadata struct {
	Version string  `json:"version"`
	Product product `json:"product"`
}

type product struct {
	Name string `json:"name"`
}

type cloudEvent struct {
	SpecVersion     string `json:"specversion"`
	ID              string `json:"id"`
	Source          string `json:"source"`
	Type            string `json:"type"`
	Subject         string `json:"subject,omitempty"`
	Time            string `json:"time"`
	DataContentType string `json:"datacontenttype"`
	Data            ocsf   `json:"data"`
}

// Envelope renders the CloudEvents 1.0 envelope with its OCSF payload.
func Envelope(id string, a Activity) ([]byte, error) {
	var why *Why
	if a.Why != (Why{}) {
		why = &a.Why
	}
	return json.Marshal(cloudEvent{
		SpecVersion:     "1.0",
		ID:              id,
		Source:          a.Source,
		Type:            a.Type,
		Subject:         a.Subject,
		Time:            a.Time.UTC().Format(time.RFC3339Nano),
		DataContentType: "application/json",
		Data: ocsf{
			ClassUID:     6003,
			CategoryUID:  6,
			ActivityID:   int(a.Kind),
			TypeUID:      6003*100 + int(a.Kind),
			SeverityID:   1,
			StatusID:     int(a.Outcome),
			StatusDetail: a.StatusDetail,
			Time:         a.Time.UnixMilli(),
			TenantID:     a.TenantID,
			Actor:        a.Actor,
			API:          api{Operation: a.Operation},
			Resources:    a.Resources,
			Why:          why,
			Metadata:     metadata{Version: OCSFVersion, Product: product{Name: "Keel"}},
		},
	})
}

// Record validates a and appends it within tx, returning its id. tx must be
// scoped to a.TenantID (store.InTenant); otherwise row-level security rejects it.
func Record(ctx context.Context, tx pgx.Tx, a Activity) (string, error) {
	if a.Time.IsZero() {
		a.Time = time.Now()
	}
	if err := a.Validate(); err != nil {
		return "", err
	}
	var id string
	if err := tx.QueryRow(ctx, `SELECT uuidv7()::text`).Scan(&id); err != nil {
		return "", fmt.Errorf("activity id: %w", err)
	}
	ev, err := Envelope(id, a)
	if err != nil {
		return "", fmt.Errorf("activity envelope: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO activities (id, tenant_id, occurred_at, source, type, subject, actor_type, actor_uid, operation, status_id, event)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		id, a.TenantID, a.Time, a.Source, a.Type, a.Subject, a.Actor.Type, a.Actor.UID, a.Operation, int(a.Outcome), ev)
	if err != nil {
		return "", fmt.Errorf("record activity: %w", err)
	}
	return id, nil
}

// Stored is an Activity as read back from the log.
type Stored struct {
	ID         string          `json:"id"`
	Seq        int64           `json:"seq"`
	OccurredAt time.Time       `json:"occurred_at"`
	LoggedAt   time.Time       `json:"logged_at"`
	Type       string          `json:"type"`
	ActorUID   string          `json:"actor_uid"`
	Operation  string          `json:"operation"`
	Event      json.RawMessage `json:"event"`
}

// Filter narrows List. Zero values mean "any".
type Filter struct {
	ActorUID  string
	Type      string
	Subject   string
	Since     time.Time
	Until     time.Time
	BeforeSeq int64 // pagination cursor: only entries with seq < BeforeSeq
	Limit     int
}

// List returns the newest matching Activities first, within tx's Tenant scope.
func List(ctx context.Context, tx pgx.Tx, f Filter) ([]Stored, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := tx.Query(ctx, `
		SELECT id::text, seq, occurred_at, logged_at, type, actor_uid, operation, event
		FROM activities
		WHERE ($1 = '' OR actor_uid = $1)
		  AND ($2 = '' OR type = $2)
		  AND ($3 = '' OR subject = $3)
		  AND ($4::timestamptz IS NULL OR occurred_at >= $4)
		  AND ($5::timestamptz IS NULL OR occurred_at < $5)
		  AND ($6 = 0 OR seq < $6)
		ORDER BY seq DESC
		LIMIT $7`,
		f.ActorUID, f.Type, f.Subject, nullTime(f.Since), nullTime(f.Until), f.BeforeSeq, f.Limit)
	if err != nil {
		return nil, fmt.Errorf("list activities: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Stored, error) {
		var s Stored
		err := r.Scan(&s.ID, &s.Seq, &s.OccurredAt, &s.LoggedAt, &s.Type, &s.ActorUID, &s.Operation, &s.Event)
		return s, err
	})
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

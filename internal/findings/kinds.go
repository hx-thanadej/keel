package findings

import (
	"database/sql/driver"
	"errors"
	"slices"
)

// Kind is a Finding kind. Its field is unexported, so the values below are the
// only kinds Go code can raise; SQL that names a kind literally is checked by
// kinds_test. The Controls registry names these to link a Control to its open
// Findings (#210).
type Kind struct{ name string }

func (k Kind) String() string { return k.name }

// Value stores a Kind as its name. The zero Kind is not a kind.
func (k Kind) Value() (driver.Value, error) {
	if k.name == "" {
		return nil, errors.New("findings: zero Kind")
	}
	return k.name, nil
}

func (k Kind) MarshalText() ([]byte, error) { return []byte(k.name), nil }

// Kinds is every Finding kind Keel raises, in declaration order.
var Kinds []Kind

func kind(name string) Kind {
	k := Kind{name}
	Kinds = append(Kinds, k)
	return k
}

var (
	AccessGrantOrphaned   = kind("access_grant_orphaned")
	BillDeliveryMissing   = kind("bill_delivery_missing")
	BillSyncBlocked       = kind("bill_sync_blocked")
	Breakglass            = kind("breakglass")
	CIIdentity            = kind("ci_identity")
	ClientRoleUnusable    = kind("client_role_unusable")
	CodeScan              = kind("code_scan")
	CostAnomaly           = kind("cost_anomaly")
	CRAReport             = kind("cra_report")
	GitHubGovernance      = kind("github_governance")
	IaC                   = kind("iac")
	LandingZoneDrift      = kind("landing_zone_drift")
	LeakedKey             = kind("leaked_key")
	MaturityAssessmentDue = kind("maturity_assessment_due")
	PDPABreach            = kind("pdpa_breach")
	PDPAResidency         = kind("pdpa_residency")
	PermissionBoundary    = kind("permission_boundary")
	Rightsizing           = kind("rightsizing")
	SAST                  = kind("sast")
	Secret                = kind("secret")
	StandingAccess        = kind("standing_access")
	UnownedFindings       = kind("unowned_findings")
	Vulnerability         = kind("vulnerability")
	Workflow              = kind("workflow")
)

// KnownKind reports whether Keel raises Findings of the kind named name.
func KnownKind(name string) bool {
	return slices.ContainsFunc(Kinds, func(k Kind) bool { return k.name == name })
}

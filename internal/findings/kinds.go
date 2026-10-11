package findings

import "slices"

// Kinds is every Finding kind Keel raises. The Controls registry names these
// to link a Policy to its open Findings (#210); kinds_test keeps the list in
// step with the code that raises them.
var Kinds = []string{
	"access_grant_orphaned",
	"bill_delivery_missing",
	"bill_sync_blocked",
	"breakglass",
	"ci_identity",
	"client_role_unusable",
	"code_scan",
	"cost_anomaly",
	"cra_report",
	"github_governance",
	"iac",
	"landing_zone_drift",
	"leaked_key",
	"maturity_assessment_due",
	"pdpa_breach",
	"pdpa_residency",
	"permission_boundary",
	"rightsizing",
	"sast",
	"secret",
	"standing_access",
	"unowned_findings",
	"vulnerability",
	"workflow",
}

// KnownKind reports whether Keel raises Findings of kind.
func KnownKind(kind string) bool { return slices.Contains(Kinds, kind) }

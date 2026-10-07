# Keel access policy (ADR-0006, DESIGN.md §5.3).
package keel.access

import rego.v1

version := "keel-access@1"

# --- Role eligibility (#132): may this Team use this template here? ---

role_needs_approval if {
	input.template.write
	input.environment.prod
}

role := {
	"allow": true,
	"reasons": [r | some r in role_notes],
	"needs_approval": role_needs_approval,
	"approvers": ["platform_admin", "security_lead"],
	"policy": version,
}

role_notes contains "write access to production is eligibility only after Platform Admin or Security Lead approval" if role_needs_approval

default role_needs_approval := false

# --- Access Grants (#133): may this person have it, for how long, with whose approval? ---

member if {
	some b in input.requester.bindings
	b.tenant_id == input.tenant_id
	b.role in {"platform_admin", "team_lead", "engineer"}
	count(object.get(b, "team_ids", [])) == 0
}

member if {
	some b in input.requester.bindings
	b.tenant_id == input.tenant_id
	b.role in {"platform_admin", "team_lead", "engineer"}
	input.role.team_id in b.team_ids
}

deny contains "only members of the eligible Team may request this role" if not member

deny contains sprintf("at most %d hours for %s", [input.template.max_hours, input.template.name]) if input.hours > input.template.max_hours

deny contains "a reason is required" if count(trim_space(input.reason)) < 10

deny contains "the role is not active for this Environment" if input.role.state != "active"

approvals := [] if {
	not input.template.write
	not input.environment.prod
}

approvals := ["team_lead"] if {
	input.template.write != input.environment.prod
}

approvals := ["team_lead", second] if {
	input.template.write
	input.environment.prod
	second := second_approver
}

second_approver := "tenant_approver" if input.tenant_requires_approval

second_approver := "security_lead" if not input.tenant_requires_approval

grant := {
	"allow": count(deny) == 0,
	"reasons": sort([r | some r in deny]),
	"approvals": approvals,
	"policy": version,
}

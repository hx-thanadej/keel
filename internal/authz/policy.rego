# Keel authorisation policy (ADR-0009, DESIGN.md §3). Default deny.
package keel.authz

import rego.v1

version := "keel-authz@1"

# Actions and the roles that may perform them. "team" scope means a binding
# narrowed to Teams only applies when the resource's team is among them.
read_roles := {"platform_admin", "security_lead", "finops_lead", "team_lead", "engineer", "tenant_viewer", "tenant_approver"}

rules := {
	"tenant.read": read_roles,
	"tenant.update": {"platform_admin"},
	"team.read": read_roles,
	"team.create": {"platform_admin"},
	"team.update": {"platform_admin"},
	"project.read": read_roles,
	"project.create": {"platform_admin", "team_lead"},
	"project.update": {"platform_admin", "team_lead"},
	"project.archive": {"platform_admin", "team_lead"},
	"environment.read": read_roles,
	"environment.create": {"platform_admin", "team_lead"},
	"environment.update": {"platform_admin", "team_lead"},
	"environment.archive": {"platform_admin", "team_lead"},
	"cloud_account.read": read_roles,
	"cloud_account.create": {"platform_admin"},
	"cloud_account.update": {"platform_admin"},
	"cloud_account.archive": {"platform_admin"},
	"service.read": read_roles,
	"service.create": {"platform_admin", "team_lead", "engineer"},
	"service.update": {"platform_admin", "team_lead", "engineer"},
	"service.archive": {"platform_admin", "team_lead"},
	"activity.read": read_roles,
	"cloud_account.discover": {"platform_admin"},
	"catalog_sync.read": {"platform_admin", "security_lead"},
	"cost.read": read_roles,
	"budget.read": read_roles,
	"finding.read": read_roles,
	"recommendation.read": read_roles,
	"recommendation.decide": {"platform_admin", "finops_lead", "team_lead", "engineer"},
	"finding.resolve": {"platform_admin", "security_lead", "finops_lead", "team_lead", "engineer"},
	"budget.create": {"platform_admin", "finops_lead", "team_lead"},
	"budget.update": {"platform_admin", "finops_lead", "team_lead"},
	"budget.archive": {"platform_admin", "finops_lead", "team_lead"},
	"cost.load": {"platform_admin", "finops_lead"},
	"cost.allocate": {"platform_admin", "finops_lead"},
	"cost.read_unallocated": {"platform_admin", "finops_lead"},
	"flow.read": read_roles,
	"flow.operate": {"platform_admin"},
	"environment.vend": {"platform_admin"},
	"environment.set_approval": {"platform_admin"},
	"release.read": read_roles,
	"release.create": {"platform_admin", "team_lead", "engineer"},
	"promotion.read": read_roles,
	"promotion.request": {"platform_admin", "team_lead", "engineer"},
	"promotion.approve": {"platform_admin", "tenant_approver"},
	"exception.read": read_roles,
	"exception.request": {"platform_admin", "security_lead", "team_lead", "engineer"},
	"exception.approve": {"security_lead", "tenant_approver"},
	"identity_provider.read": {"platform_admin", "security_lead"},
	"identity_provider.create": {"platform_admin"},
	"identity_provider.update": {"platform_admin"},
}

# A binding is usable only in the principal's own Tenant, unless the principal
# belongs to the home Tenant (home staff are bound into client Tenants they serve).
usable(b) if input.principal.home
usable(b) if b.tenant_id == input.principal.tenant_id

team_ok(b) if count(object.get(b, "team_ids", [])) == 0
team_ok(b) if input.resource.team_id in b.team_ids

# Creating a Tenant: only a platform admin of the home Tenant.
allow_reasons contains "home platform_admin may create tenants" if {
	input.action == "tenant.create"
	input.principal.home
	some b in input.principal.bindings
	b.role == "platform_admin"
	b.tenant_id == input.principal.tenant_id
}

allow_reasons contains sprintf("role %s in tenant", [b.role]) if {
	input.action != "tenant.create"
	roles := rules[input.action]
	some b in input.principal.bindings
	usable(b)
	b.tenant_id == input.resource.tenant_id
	b.role in roles
	team_ok(b)
}

default decision := {"allow": false, "reason": "no matching binding", "policy": "keel-authz@1"}

# Several bindings may allow the same action; report the first reason, sorted, for stability.
decision := {"allow": true, "reason": sort(allow_reasons)[0], "policy": version} if count(allow_reasons) > 0

decision := {"allow": false, "reason": "unknown action", "policy": version} if {
	input.action != "tenant.create"
	not rules[input.action]
}

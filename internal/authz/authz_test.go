package authz_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hx-thanadej/keel/internal/auth"
	"github.com/hx-thanadej/keel/internal/authz"
)

const (
	home  = "00000000-0000-4000-8000-00000000000h"
	tat   = "00000000-0000-4000-8000-0000000000a1"
	acme  = "00000000-0000-4000-8000-0000000000b2"
	teamA = "team-crm"
	teamB = "team-other"
)

func principal(tenant string, isHome bool, bindings ...auth.Binding) auth.Principal {
	return auth.Principal{Subject: "user:x", Kind: auth.KindHuman, TenantID: tenant, Home: isHome, Bindings: bindings}
}

func bind(role, tenant string, teams ...string) auth.Binding {
	return auth.Binding{Role: role, TenantID: tenant, TeamIDs: teams}
}

func TestDecide(t *testing.T) {
	az, err := authz.New()
	if err != nil {
		t.Fatal(err)
	}
	inTAT := authz.Resource{Type: "project", TenantID: tat, TeamID: teamA}

	cases := []struct {
		name   string
		p      auth.Principal
		action string
		res    authz.Resource
		allow  bool
	}{
		// Default deny.
		{"no bindings", principal(tat, false), "project.read", inTAT, false},
		{"unknown action", principal(home, true, bind(auth.RolePlatformAdmin, tat)), "project.explode", inTAT, false},

		// Tenant creation: only a home-tenant platform admin.
		{"home admin creates tenant", principal(home, true, bind(auth.RolePlatformAdmin, home)), "tenant.create", authz.Resource{Type: "tenant"}, true},
		{"client admin cannot create tenant", principal(tat, false, bind(auth.RolePlatformAdmin, tat)), "tenant.create", authz.Resource{Type: "tenant"}, false},
		{"home engineer cannot create tenant", principal(home, true, bind(auth.RoleEngineer, home)), "tenant.create", authz.Resource{Type: "tenant"}, false},

		// Reads: any role bound in that tenant.
		{"viewer reads own tenant project", principal(tat, false, bind(auth.RoleTenantViewer, tat)), "project.read", inTAT, true},
		{"viewer reads activity", principal(tat, false, bind(auth.RoleTenantViewer, tat)), "activity.read", authz.Resource{Type: "activity", TenantID: tat}, true},
		{"viewer cannot read other tenant", principal(tat, false, bind(auth.RoleTenantViewer, tat)), "project.read", authz.Resource{Type: "project", TenantID: acme}, false},

		// Cross-tenant isolation for operators: no implicit access (Access Grants come in M5).
		{"home admin has no implicit access to client", principal(home, true, bind(auth.RolePlatformAdmin, home)), "project.read", inTAT, false},
		{"home engineer bound in client tenant", principal(home, true, bind(auth.RoleEngineer, tat, teamA)), "project.read", inTAT, true},

		// A Tenant Member can only hold bindings in their own Tenant.
		{"tenant member binding elsewhere is ignored", principal(acme, false, bind(auth.RoleTeamLead, tat)), "project.read", inTAT, false},

		// Writes.
		{"viewer cannot write", principal(tat, false, bind(auth.RoleTenantViewer, tat)), "project.update", inTAT, false},
		{"team lead creates project for own team", principal(home, true, bind(auth.RoleTeamLead, tat, teamA)), "project.create", inTAT, true},
		{"team lead cannot touch other team's project", principal(home, true, bind(auth.RoleTeamLead, tat, teamB)), "project.update", inTAT, false},
		{"tenant-wide team lead", principal(home, true, bind(auth.RoleTeamLead, tat)), "project.archive", inTAT, true},
		{"engineer cannot create project", principal(home, true, bind(auth.RoleEngineer, tat, teamA)), "project.create", inTAT, false},
		{"engineer creates service in own team", principal(home, true, bind(auth.RoleEngineer, tat, teamA)), "service.create", authz.Resource{Type: "service", TenantID: tat, TeamID: teamA}, true},
		{"team lead creates environment", principal(home, true, bind(auth.RoleTeamLead, tat, teamA)), "environment.create", authz.Resource{Type: "environment", TenantID: tat, TeamID: teamA}, true},
		{"only platform admin registers cloud accounts", principal(home, true, bind(auth.RoleTeamLead, tat, teamA)), "cloud_account.create", authz.Resource{Type: "cloud_account", TenantID: tat, TeamID: teamA}, false},
		{"platform admin bound in tenant registers cloud account", principal(home, true, bind(auth.RolePlatformAdmin, tat)), "cloud_account.create", authz.Resource{Type: "cloud_account", TenantID: tat}, true},
		{"platform admin manages teams", principal(home, true, bind(auth.RolePlatformAdmin, home)), "team.create", authz.Resource{Type: "team", TenantID: home}, true},
		{"team lead cannot manage teams", principal(home, true, bind(auth.RoleTeamLead, home)), "team.create", authz.Resource{Type: "team", TenantID: home}, false},
		{"several matching bindings", principal(home, true, bind(auth.RoleTeamLead, tat, teamA), bind(auth.RoleEngineer, tat, teamA)), "service.create", authz.Resource{Type: "service", TenantID: tat, TeamID: teamA}, true},
		{"finops lead reads", principal(home, true, bind(auth.RoleFinOpsLead, tat)), "project.read", inTAT, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := az.Decide(context.Background(), authz.Request{Principal: c.p, Action: c.action, Resource: c.res})
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow != c.allow {
				t.Fatalf("allow = %v, want %v (reason %q)", d.Allow, c.allow, d.Reason)
			}
			if d.Reason == "" {
				t.Error("decision has no reason")
			}
		})
	}
}

func TestDecisionNamesPolicyVersion(t *testing.T) {
	az, _ := authz.New()
	d, err := az.Decide(context.Background(), authz.Request{Principal: principal(tat, false), Action: "project.read", Resource: authz.Resource{TenantID: tat}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Policy == "" {
		t.Fatal("decision must name the policy version for the Activity Log")
	}
	_ = fmt.Sprint(d)
}

// Package access governs human access to cloud accounts (M5, ADR-0006):
// role templates, which Teams may use them where (#132), time-boxed Access
// Grants (#133) and the standing-access report (#134). Humans reach member
// accounts only through Cloud Identity Center role configurations that Keel
// creates and assigns for hours, inside each account's Permission Boundary.
package access

import "encoding/json"

// Template is a role a Team can be made eligible for.
type Template struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Write       bool     `json:"write"` // changes resources (higher risk)
	MaxHours    int      `json:"max_hours"`
	Actions     []string `json:"actions"`
}

// Templates is keel-access-templates@1.
var Templates = map[string]Template{
	"read-only": {Name: "read-only", Description: "Describe/List/Get on the Project's services", MaxHours: 8,
		Actions: []string{"*:Describe*", "*:List*", "*:Get*", "monitor:*", "cls:Search*"}},
	"data-reader": {Name: "data-reader", Description: "Read objects and database metadata; no secrets", MaxHours: 4,
		Actions: []string{"cos:GetObject", "cos:HeadObject", "cos:GetBucket", "cdb:Describe*", "postgres:Describe*"}},
	"deployer": {Name: "deployer", Description: "Kubernetes and registry operations for releases", Write: true, MaxHours: 4,
		Actions: []string{"tke:*", "tcr:*", "clb:Describe*", "monitor:*", "cls:*"}},
	"operator": {Name: "operator", Description: "Operate compute, networking and storage", Write: true, MaxHours: 2,
		Actions: []string{"cvm:*", "cbs:*", "clb:*", "tke:*", "vpc:*", "monitor:*", "cls:*"}},
}

// PolicyDocument is the template's CAM policy (the account's Permission
// Boundary still caps it).
func (t Template) PolicyDocument() string {
	b, _ := json.Marshal(map[string]any{"version": "2.0", "statement": []any{map[string]any{"effect": "allow", "action": t.Actions, "resource": []string{"*"}}}})
	return string(b)
}

// RoleConfigurationName is the Identity Center role configuration name.
func (t Template) RoleConfigurationName() string { return "keel-" + t.Name }

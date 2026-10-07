# Keel promotion policy (ADR-0008, ADR-0009). A Promotion opens a pull
# request only when no rule below objects.
package keel.promotion

import rego.v1

version := "keel-promotion@1"

digest_re := `^sha256:[a-f0-9]{64}$`

deny contains msg if {
	some img in input.release.images
	not regex.match(digest_re, img.digest)
	msg := sprintf("image %s is not pinned by digest", [img.name])
}

deny contains "release has no images" if count(input.release.images) == 0

deny contains msg if {
	input.previous != null
	not input.previous.deployed
	msg := sprintf("release is not deployed to %s yet", [input.previous.name])
}

deny contains msg if {
	input.budget.hard_breach
	msg := sprintf("budget hard-breached: %s", [input.budget.detail])
}

deny contains msg if {
	input.findings.critical_open > 0
	msg := sprintf("%d open critical Findings on this Project without an Exception", [input.findings.critical_open])
}

deny contains "the Project has no config repository" if input.config_repo == ""

deny contains "release has no passing provenance verification (VSA) for every image" if {
	input.vsa.required
	not input.vsa.passed
}

needs_approval if {
	input.environment.requires_approval
	not input.approval.given
}

decision := {
	"allow": count(deny) == 0,
	"reasons": sort([r | some r in deny]),
	"needs_approval": needs_approval,
	"policy": version,
}

default needs_approval := false

---
status: accepted
date: 2026-10-07
deciders: thanadej@harmonyx.co
---

# CI pushes to the shared registry with Keel-brokered one-hour tokens

## Context

Every Project has a namespace in one TCR Enterprise instance in the platform
account (#94). A CI run proves its identity with GitHub's OIDC token, which
the Environment account's deploy role trusts (ADR-0007, #90), but that role
cannot reach a registry in another account. TCR logins are instance tokens;
CAM temporary credentials do not log in to TCR directly.

## Decision

The publish job of Keel's reusable workflow sends its OIDC token to Keel
(`POST /services/{service}/registry-token`). Keel verifies the token, maps
`repository_id` to the Service, and asks TCR for a **temporary** instance token
(one hour; never `longterm`). Every issue is an Activity. No registry secret is
stored in GitHub.

A TCR instance token is not namespace-scoped, so scoping is enforced where it
matters: a Release may name only images under its Project's namespace, and
only a Release with a passing provenance verification (ADR-0010, #112) can be
promoted. An image pushed elsewhere with a borrowed token can never run.

## Considered options

- **Two-hop CAM roles** (member deploy role → platform-account push role):
  still ends in an instance token; more trust policies to keep in step.
- **Long-term TCR tokens per Project in GitHub secrets**: violates ADR-0007.
- **Registry per Environment account**: per-instance cost multiplied by every
  Environment.

## Consequences

- Keel is in the push path: if Keel is down, builds still run but cannot push.
- Revisit if TCR adds namespace-scoped temporary tokens.

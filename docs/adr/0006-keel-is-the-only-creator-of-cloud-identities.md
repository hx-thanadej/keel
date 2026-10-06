---
status: proposed
date: 2026-10-06
---

# Keel is the only creator of cloud IAM identities

Teams self-serve cloud permissions *within* a **Permission Boundary**, the
AWS model. On AWS this is enforceable natively (an SCP condition on
`iam:PermissionsBoundary` forces delegated admins to attach the boundary). Tencent
CAM supports boundaries, but we found no condition key that forces a boundary
onto roles or users a delegate creates. So on every provider Keel is the
**sole creator of IAM roles and users**: an organisation-level policy (Tencent
service control policy, AWS SCP) denies role/user creation and boundary
changes to every principal except Keel's automation role. Teams request roles
through Keel's API, where policy checks the request, Keel stamps the boundary,
and the request is recorded as an Activity.

## Consequences

- One behaviour across clouds, at the cost of Keel being on the critical path
  for IAM changes. Break-glass exists for when Keel is down.
- Human production access is **not standing**: humans hold read-only by default
  and get Access Grants (time-boxed, justified, auto-revoked) through Keel.
- Break-glass: ≥2 provider-native admin identities outside SSO, hardware MFA,
  split custody, alert on every use, post-mortem, drill every 90 days.

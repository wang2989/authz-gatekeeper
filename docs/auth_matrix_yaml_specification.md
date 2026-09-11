# Specification: Declarative Authorization Policy (`auth-matrix.yaml`)

This specification defines the syntax, schema requirements, and resolution semantics for `auth-matrix.yaml` in **Authz CI Gatekeeper (`authz-gatekeeper`)**.

---

## 1. Design Philosophy

1. **Human-Centric & Maintainable**: Configuration must be concise, expressive, and easily edited by developers without boilerplate.
2. **Flexible Role Definitions**: Supports ordered rank lists (`[SuperAdmin, OrgAdmin, Member, Viewer]`) as well as directed inheritance graphs (`inherits: [ParentRole]`).
3. **Layered Precedence**:
   - **Layer 1 (Highest Precedence)**: Explicit OpenAPI annotations (`x-required-role`, `security: []`, `x-allow-anonymous`).
   - **Layer 2**: Exact route rules in `auth-matrix.yaml` (`/api/v1/admin/audit`).
   - **Layer 3**: Glob/wildcard path pattern rules in `auth-matrix.yaml` (`/api/v1/admin/*`).
   - **Layer 4**: Method-level defaults (`GET: Viewer`, `DELETE: OrgAdmin`).
   - **Layer 5 (Baseline)**: Global zero-trust fallback (deny unmapped protected routes).
4. **Deterministic Validation**: Strict cycle detection preventing recursive inheritance; explicit validation of unknown parent roles.

---

## 2. Schema Specification

### Top-Level Properties

| Field | Type | Required? | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `version` | `string` | **Required** | None | Schema version, e.g. `"1"` or `"1.0"`. |
| `roles` | `map` \| `array` | **Required** | None | Role definitions and inheritance rules. |
| `tenants` | `object` | Optional | `{ model: "flat" }` | Multi-tenant isolation model and mock tenant contexts. |
| `jwt` | `object` | Optional | `{ ... }` | Claim mappings for JWT identity synthesis. |
| `defaults` | `object` | Optional | `{ ... }` | Fallback authorization rules when routes lack annotations. |
| `routes` | `array` | Optional | `[]` | Path-level role requirements, glob wildcards, and bypasses. |
| `parameters` | `object` | Optional | `{}` | Seeded entity IDs for dynamic `{param}` placeholders. |

---

### Detailed Property Definitions

#### 1. `roles` (Required)
Defines all recognized authorization personas and their inheritance relationships. Supports two intuitive authoring formats:

##### Format A: Map with `inherits` (Recommended for complex RBAC graphs)
```yaml
roles:
  SuperAdmin:
    inherits: [OrgAdmin]
    description: Full system administrator
  OrgAdmin:
    inherits: [Member]
    description: Tenant administrator
  Member:
    inherits: [Viewer]
    description: Standard tenant user
  Viewer:
    inherits: []
    description: Read-only access
```
*(Note: `inherits` accepts either a list `[OrgAdmin]` or a single string `OrgAdmin`).*

##### Format B: Ordered Hierarchy List (Shorthand for linear RBAC)
```yaml
roles:
  - SuperAdmin
  - OrgAdmin
  - Member
  - Viewer
```
*(Each role implicitly inherits all roles declared below it: `SuperAdmin > OrgAdmin > Member > Viewer`).*

#### 2. `tenants` (Optional)
Configures multi-tenant testing boundaries for BOLA/IDOR detection.

```yaml
tenants:
  model: flat # "flat" (default, sibling tenants) or "hierarchical" (parent/child orgs)
  fixtures:
    primary:
      id: "tenant-alpha"
      name: "Acme Corp (Primary)"
    secondary:
      id: "tenant-beta"
      name: "Cyberdyne Systems (Attacker)"
```

#### 3. `jwt` (Optional)
Maps claim names so the Gatekeeper's mock token synthesizer creates tokens matching the target application's expected JWT payload.

```yaml
jwt:
  algorithm: HS256 # HS256 (default), HS384, HS512, RS256, ES256
  role_claim: "role" # or "roles", "realm_access.roles", "permissions"
  tenant_claim: "tenant_id" # or "org_id", "tid"
  user_id_claim: "sub" # or "uid", "user_id"
  issuer: "gatekeeper" # optional iss claim
  audience: "gatekeeper-api" # optional aud claim
```

#### 4. `defaults` (Optional)
Sets baseline rules when an endpoint has no explicit OpenAPI vendor annotations (`x-required-role`) and no matching rule in `routes`.

```yaml
defaults:
  unauthenticated_access: deny # "deny" (default: expect 401/403) or "allow"
  default_role: OrgAdmin # Fallback role for protected routes without explicit roles
  method_defaults:
    GET: Viewer
    POST: Member
    PUT: Member
    PATCH: Member
    DELETE: OrgAdmin
```

#### 5. `routes` (Optional)
Declarative path-level authorization rules. Supports exact paths and glob patterns (`*`, `**`).

```yaml
routes:
  - path: "/api/v1/health"
    allow_anonymous: true

  - path: "/api/v1/public/*"
    allow_anonymous: true

  - path: "/api/v1/admin/*"
    roles: [SuperAdmin]

  - path: "/api/v1/{tenant_id}/billing/*"
    roles: [OrgAdmin]
    methods: [GET, POST, PUT]
```

#### 6. `parameters` (Optional)
Seeded mock values for path parameters (e.g., `{tenant_id}`, `{project_id}`) to test real resources or seeded fixtures.

```yaml
parameters:
  tenant_id:
    primary: "tenant-alpha"
    secondary: "tenant-beta"
  project_id:
    primary: "proj-100"
    secondary: "proj-200"
```

---

## 3. Inheritance & Cycle Resolution

The parser computes the **Transitive Role Permission Set** for every role:
- If `SuperAdmin` inherits `OrgAdmin`, and `OrgAdmin` inherits `Member`:
  $$\text{Permissions}(\text{SuperAdmin}) = \{\text{SuperAdmin}, \text{OrgAdmin}, \text{Member}, \text{Viewer}\}$$
- When a route requires role `Member`, any user with `Member`, `OrgAdmin`, or `SuperAdmin` is authorized.
- **Cycle Detection**:
  - The policy parser constructs a Directed Graph $G = (V, E)$ of role inheritance.
  - Using depth-first search (DFS) with recursion state coloring (White/Gray/Black), any back-edge immediately triggers `PolicyValidationError` with the exact cycle path (e.g., `Cyclic role inheritance detected: Admin -> Manager -> Admin`).
- **Undefined Parent Detection**:
  - If role `Editor` inherits `Contributor` but `Contributor` is not defined in `roles`, throws `PolicyValidationError: Role "Editor" inherits from undefined role "Contributor"`.

---

## 4. Reconciliation Order of Precedence

When binding an endpoint operation to an authorization contract:

```
┌────────────────────────────────────────────────────────┐
│ 1. Explicit OpenAPI Operation Tag (x-required-role)     │ (Highest Precedence)
└───────────────────────────┬────────────────────────────┘
                            │ (If not specified)
                            ▼
┌────────────────────────────────────────────────────────┐
│ 2. Exact Path Match in routes: (/api/v1/admin/users)   │
└───────────────────────────┬────────────────────────────┘
                            │ (If no exact match)
                            ▼
┌────────────────────────────────────────────────────────┐
│ 3. Glob Pattern Match in routes: (/api/v1/admin/*)     │
└───────────────────────────┬────────────────────────────┘
                            │ (If no glob match)
                            ▼
┌────────────────────────────────────────────────────────┐
│ 4. Method Default: (defaults.method_defaults[DELETE])  │
└───────────────────────────┬────────────────────────────┘
                            │ (If no method default)
                            ▼
┌────────────────────────────────────────────────────────┐
│ 5. Global Zero-Trust Default (defaults.default_role)   │ (Fallback)
└────────────────────────────────────────────────────────┘
```


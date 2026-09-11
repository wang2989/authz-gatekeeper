import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  parseAuthPolicy,
  loadAuthPolicy,
  PolicyValidationError,
  PolicySyntaxError,
} from '../../src/parser/policy-parser.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

describe('Declarative Auth Matrix Parser (src/parser/policy-parser.js)', () => {
  describe('Full Production Fixture (Format A: Inheritance Map)', () => {
    it('loads and validates auth-matrix.fixture.yaml completely', async () => {
      const fixturePath = join(FIXTURES_DIR, 'auth-matrix.fixture.yaml');
      const policy = await loadAuthPolicy(fixturePath);

      assert.equal(policy.version, '1');
      assert.deepEqual(policy.roles, ['SuperAdmin', 'OrgAdmin', 'Member', 'Viewer']);
      assert.equal(policy.tenants.model, 'flat');
      assert.equal(policy.tenants.fixtures.primary.id, 'tenant-alpha');
      assert.equal(policy.tenants.fixtures.secondary.id, 'tenant-beta');
      assert.equal(policy.jwt.algorithm, 'HS256');
      assert.equal(policy.jwt.role_claim, 'role');
      assert.equal(policy.defaults.unauthenticated_access, 'deny');
      assert.equal(policy.defaults.default_role, 'OrgAdmin');
      assert.equal(policy.defaults.method_defaults.DELETE, 'OrgAdmin');
      assert.equal(policy.defaults.method_defaults.GET, 'Viewer');
      assert.equal(policy.parameters.tenant_id.primary, 'tenant-alpha');
      assert.equal(policy.parameters.project_id.secondary, 'proj-200');
    });

    it('computes correct transitive role permissions', async () => {
      const fixturePath = join(FIXTURES_DIR, 'auth-matrix.fixture.yaml');
      const policy = await loadAuthPolicy(fixturePath);

      // SuperAdmin inherits OrgAdmin -> Member -> Viewer
      const superAdminTransitive = policy.getTransitiveRoles('SuperAdmin');
      assert.ok(superAdminTransitive.includes('SuperAdmin'));
      assert.ok(superAdminTransitive.includes('OrgAdmin'));
      assert.ok(superAdminTransitive.includes('Member'));
      assert.ok(superAdminTransitive.includes('Viewer'));

      // Viewer only inherits Viewer
      const viewerTransitive = policy.getTransitiveRoles('Viewer');
      assert.deepEqual(viewerTransitive, ['Viewer']);
    });

    it('computes correct authorized caller sets for required roles', async () => {
      const fixturePath = join(FIXTURES_DIR, 'auth-matrix.fixture.yaml');
      const policy = await loadAuthPolicy(fixturePath);

      // When route requires Viewer, all roles can access
      const viewerCallers = policy.getAuthorizedCallers('Viewer');
      assert.deepEqual(viewerCallers.sort(), ['Member', 'OrgAdmin', 'SuperAdmin', 'Viewer'].sort());

      // When route requires OrgAdmin, only OrgAdmin and SuperAdmin can access
      const orgAdminCallers = policy.getAuthorizedCallers('OrgAdmin');
      assert.deepEqual(orgAdminCallers.sort(), ['OrgAdmin', 'SuperAdmin'].sort());

      // When route requires SuperAdmin, only SuperAdmin can access
      const superAdminCallers = policy.getAuthorizedCallers('SuperAdmin');
      assert.deepEqual(superAdminCallers, ['SuperAdmin']);
    });

    it('evaluates isRoleAuthorized accurately', async () => {
      const fixturePath = join(FIXTURES_DIR, 'auth-matrix.fixture.yaml');
      const policy = await loadAuthPolicy(fixturePath);

      assert.equal(policy.isRoleAuthorized('SuperAdmin', ['Viewer']), true);
      assert.equal(policy.isRoleAuthorized('SuperAdmin', ['OrgAdmin']), true);
      assert.equal(policy.isRoleAuthorized('OrgAdmin', ['Member']), true);
      assert.equal(policy.isRoleAuthorized('Member', ['OrgAdmin']), false);
      assert.equal(policy.isRoleAuthorized('Viewer', ['SuperAdmin']), false);
      assert.equal(policy.isRoleAuthorized('UnknownRole', ['Viewer']), false);
      assert.equal(policy.isRoleAuthorized('Viewer', []), false);
    });

    it('matches exact and glob route rules with method filtering', async () => {
      const fixturePath = join(FIXTURES_DIR, 'auth-matrix.fixture.yaml');
      const policy = await loadAuthPolicy(fixturePath);

      // Public exact route
      const healthRule = policy.findMatchingRouteRule('/health', 'GET');
      assert.ok(healthRule);
      assert.equal(healthRule.allow_anonymous, true);

      // Project GET rule (requires Viewer)
      const projectGetRule = policy.findMatchingRouteRule('/api/v1/{tenant_id}/projects', 'GET');
      assert.ok(projectGetRule);
      assert.deepEqual(projectGetRule.roles, ['Viewer']);

      // Project POST rule (requires OrgAdmin)
      const projectPostRule = policy.findMatchingRouteRule('/api/v1/{tenant_id}/projects', 'POST');
      assert.ok(projectPostRule);
      assert.deepEqual(projectPostRule.roles, ['OrgAdmin']);

      // Wildcard admin route (/api/v1/{tenant_id}/admin/*)
      const adminSettingsRule = policy.findMatchingRouteRule('/api/v1/{tenant_id}/admin/settings', 'GET');
      assert.ok(adminSettingsRule);
      assert.deepEqual(adminSettingsRule.roles, ['SuperAdmin']);

      // Wildcard project delete (/api/v1/{tenant_id}/projects/*)
      const deleteProjRule = policy.findMatchingRouteRule('/api/v1/{tenant_id}/projects/proj-100', 'DELETE');
      assert.ok(deleteProjRule);
      assert.deepEqual(deleteProjRule.roles, ['OrgAdmin']);

      // Unmatched route returns null
      const unmatched = policy.findMatchingRouteRule('/unknown/path', 'GET');
      assert.equal(unmatched, null);
    });
  });

  describe('Minimal Fixture (Format B: Ordered List)', () => {
    it('loads and establishes linear hierarchy implicitly', async () => {
      const fixturePath = join(FIXTURES_DIR, 'auth-matrix-minimal.fixture.yaml');
      const policy = await loadAuthPolicy(fixturePath);

      assert.equal(policy.version, '1');
      assert.deepEqual(policy.roles, ['SuperAdmin', 'OrgAdmin', 'Member', 'Viewer']);

      assert.equal(policy.isRoleAuthorized('SuperAdmin', ['Member']), true);
      assert.equal(policy.isRoleAuthorized('OrgAdmin', ['Viewer']), true);
      assert.equal(policy.isRoleAuthorized('Member', ['SuperAdmin']), false);
    });
  });

  describe('Hierarchical Multi-Tenant Fixture', () => {
    it('loads hierarchical tenant model correctly', async () => {
      const fixturePath = join(FIXTURES_DIR, 'auth-matrix-hierarchical.fixture.yaml');
      const policy = await loadAuthPolicy(fixturePath);

      assert.equal(policy.tenants.model, 'hierarchical');
      assert.equal(policy.tenants.fixtures.primary.id, 'org-parent');
      assert.equal(policy.tenants.fixtures.secondary.parent_id, 'org-parent');
      assert.equal(policy.isRoleAuthorized('Admin', ['Viewer']), true);
      assert.equal(policy.isRoleAuthorized('Viewer', ['Admin']), false);
    });
  });

  describe('Validation and Error Handling', () => {
    it('throws when policy file does not exist', async () => {
      await assert.rejects(
        async () => {
          await loadAuthPolicy(join(FIXTURES_DIR, 'non-existent.yaml'));
        },
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.equal(err.code, 'ERR_POLICY_FILE_NOT_FOUND');
          return true;
        }
      );
    });

    it('throws when policy content is empty', () => {
      assert.throws(
        () => parseAuthPolicy('   '),
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          return true;
        }
      );
    });

    it('throws PolicySyntaxError on malformed YAML syntax', () => {
      const malformed = `
version: "1"
roles:
  - Admin
    indent_error: true
`;
      assert.throws(
        () => parseAuthPolicy(malformed),
        (err) => {
          assert.ok(err instanceof PolicySyntaxError);
          return true;
        }
      );
    });

    it('throws when version property is missing', async () => {
      const fixturePath = join(FIXTURES_DIR, 'invalid', 'auth-matrix-missing-version.yaml');
      await assert.rejects(
        async () => {
          await loadAuthPolicy(fixturePath);
        },
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /Missing required property 'version'/);
          return true;
        }
      );
    });

    it('throws when version is not a string', () => {
      assert.throws(
        () => parseAuthPolicy({ version: 1, roles: ['Admin'] }),
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /Property 'version' must be a non-empty string/);
          return true;
        }
      );
    });

    it('throws when roles property is missing', async () => {
      const fixturePath = join(FIXTURES_DIR, 'invalid', 'auth-matrix-missing-roles.yaml');
      await assert.rejects(
        async () => {
          await loadAuthPolicy(fixturePath);
        },
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /Missing required property 'roles'/);
          return true;
        }
      );
    });

    it('throws when roles array is empty', () => {
      assert.throws(
        () => parseAuthPolicy({ version: '1', roles: [] }),
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /Property 'roles' array cannot be empty/);
          return true;
        }
      );
    });

    it('throws when duplicate roles appear in ordered list', () => {
      assert.throws(
        () => parseAuthPolicy({ version: '1', roles: ['Admin', 'Admin'] }),
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /Duplicate role "Admin" found/);
          return true;
        }
      );
    });

    it('throws when circular role inheritance is detected', async () => {
      const fixturePath = join(FIXTURES_DIR, 'invalid', 'auth-matrix-cyclic.yaml');
      await assert.rejects(
        async () => {
          await loadAuthPolicy(fixturePath);
        },
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /Cyclic role inheritance detected/);
          assert.match(err.message, /RoleA/);
          return true;
        }
      );
    });

    it('throws when a role inherits from an undefined parent', async () => {
      const fixturePath = join(FIXTURES_DIR, 'invalid', 'auth-matrix-unknown-parent.yaml');
      await assert.rejects(
        async () => {
          await loadAuthPolicy(fixturePath);
        },
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /Role "Admin" inherits from undefined role "NonExistentRole"/);
          return true;
        }
      );
    });

    it('throws when defaults.default_role references an undeclared role', () => {
      assert.throws(
        () =>
          parseAuthPolicy({
            version: '1',
            roles: ['Admin'],
            defaults: { default_role: 'GhostRole' },
          }),
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /Default role "GhostRole" is not declared in 'roles'/);
          return true;
        }
      );
    });

    it('throws when defaults.method_defaults references an undeclared role', () => {
      assert.throws(
        () =>
          parseAuthPolicy({
            version: '1',
            roles: ['Admin'],
            defaults: { method_defaults: { DELETE: 'GhostRole' } },
          }),
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /Method default for DELETE references undeclared role "GhostRole"/);
          return true;
        }
      );
    });

    it('throws when route references an undeclared role', () => {
      assert.throws(
        () =>
          parseAuthPolicy({
            version: '1',
            roles: ['Admin'],
            routes: [{ path: '/api/test', roles: ['GhostRole'] }],
          }),
        (err) => {
          assert.ok(err instanceof PolicyValidationError);
          assert.match(err.message, /references undeclared role "GhostRole"/);
          return true;
        }
      );
    });
  });
});


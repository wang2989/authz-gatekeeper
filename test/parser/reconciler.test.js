import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadOpenApiSpec } from '../../src/parser/openapi-loader.js';
import { extractEndpoints } from '../../src/parser/openapi-extractor.js';
import { loadAuthPolicy, parseAuthPolicy } from '../../src/parser/policy-parser.js';
import { reconcile, ReconciliationError, RULE_SOURCES } from '../../src/parser/reconciler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

describe('Policy & Schema Reconciliation Engine (src/parser/reconciler.js)', () => {
  describe('Standard Fixture Reconciliation (openapi.fixture.yaml + auth-matrix.fixture.yaml)', () => {
    it('reconciles all extracted endpoints into structured contracts', async () => {
      const spec = await loadOpenApiSpec(join(FIXTURES_DIR, 'openapi.fixture.yaml'));
      const endpoints = extractEndpoints(spec);
      const policy = await loadAuthPolicy(join(FIXTURES_DIR, 'auth-matrix.fixture.yaml'));

      const report = reconcile(endpoints, policy);

      assert.equal(report.contracts.length, 7);
      assert.equal(report.summary.totalEndpoints, 7);
      assert.equal(report.summary.protectedEndpoints, 6);
      assert.equal(report.summary.anonymousEndpoints, 1);
      assert.equal(report.summary.tenantBoundaryEndpoints, 6);
      assert.equal(report.warnings.length, 0);
    });

    it('correctly classifies anonymous public route (/health)', async () => {
      const spec = await loadOpenApiSpec(join(FIXTURES_DIR, 'openapi.fixture.yaml'));
      const endpoints = extractEndpoints(spec);
      const policy = await loadAuthPolicy(join(FIXTURES_DIR, 'auth-matrix.fixture.yaml'));

      const report = reconcile(endpoints, policy);
      const healthContract = report.contracts.find((c) => c.path === '/health');

      assert.ok(healthContract);
      assert.equal(healthContract.isAnonymous, true);
      assert.deepEqual(healthContract.requiredRoles, []);
      assert.deepEqual(healthContract.authorizedRoles, []);
      assert.deepEqual(healthContract.unauthorizedRoles, []);
      assert.equal(healthContract.hasTenantBoundary, false);
      assert.equal(healthContract.ruleSource, RULE_SOURCES.OPENAPI_ANNOTATION);
    });

    it('reconciles roles and role inheritance on protected endpoints', async () => {
      const spec = await loadOpenApiSpec(join(FIXTURES_DIR, 'openapi.fixture.yaml'));
      const endpoints = extractEndpoints(spec);
      const policy = await loadAuthPolicy(join(FIXTURES_DIR, 'auth-matrix.fixture.yaml'));

      const report = reconcile(endpoints, policy);

      // POST /api/v1/{tenant_id}/projects requires OrgAdmin and SuperAdmin in OpenAPI
      const postProjectContract = report.contracts.find(
        (c) => c.path === '/api/v1/{tenant_id}/projects' && c.method === 'POST'
      );

      assert.ok(postProjectContract);
      assert.equal(postProjectContract.isAnonymous, false);
      assert.deepEqual(postProjectContract.requiredRoles.sort(), ['OrgAdmin', 'SuperAdmin'].sort());
      // Authorized roles: OrgAdmin and SuperAdmin
      assert.deepEqual(postProjectContract.authorizedRoles.sort(), ['OrgAdmin', 'SuperAdmin'].sort());
      // Unauthorized roles: Viewer and Member
      assert.deepEqual(postProjectContract.unauthorizedRoles.sort(), ['Member', 'Viewer'].sort());

      // GET /api/v1/{tenant_id}/admin/settings requires SuperAdmin
      const adminSettingsContract = report.contracts.find(
        (c) => c.path === '/api/v1/{tenant_id}/admin/settings' && c.method === 'GET'
      );

      assert.ok(adminSettingsContract);
      assert.equal(adminSettingsContract.isAnonymous, false);
      assert.deepEqual(adminSettingsContract.requiredRoles, ['SuperAdmin']);
      assert.deepEqual(adminSettingsContract.authorizedRoles, ['SuperAdmin']);
      assert.deepEqual(adminSettingsContract.unauthorizedRoles.sort(), ['Member', 'OrgAdmin', 'Viewer'].sort());
    });

    it('binds multi-tenant fixtures and detects BOLA test boundaries', async () => {
      const spec = await loadOpenApiSpec(join(FIXTURES_DIR, 'openapi.fixture.yaml'));
      const endpoints = extractEndpoints(spec);
      const policy = await loadAuthPolicy(join(FIXTURES_DIR, 'auth-matrix.fixture.yaml'));

      const report = reconcile(endpoints, policy);

      const projectDetailContract = report.contracts.find(
        (c) => c.path === '/api/v1/{tenant_id}/projects/{project_id}' && c.method === 'GET'
      );

      assert.ok(projectDetailContract);
      assert.equal(projectDetailContract.hasTenantBoundary, true);
      assert.equal(projectDetailContract.tenantParameter, 'tenant_id');
      assert.equal(projectDetailContract.fixtures.primary.tenant_id, 'tenant-alpha');
      assert.equal(projectDetailContract.fixtures.secondary.tenant_id, 'tenant-beta');
      assert.equal(projectDetailContract.fixtures.primary.project_id, 'proj-100');
      assert.equal(projectDetailContract.fixtures.secondary.project_id, 'proj-200');
    });
  });

  describe('5-Layer Precedence Resolution', () => {
    const basePolicyYaml = `
version: "1"
roles:
  SuperAdmin:
    inherits: [OrgAdmin]
  OrgAdmin:
    inherits: [Member]
  Member:
    inherits: [Viewer]
  Viewer:
    inherits: []
defaults:
  unauthenticated_access: deny
  default_role: Viewer
  method_defaults:
    DELETE: OrgAdmin
routes:
  - path: "/api/v1/exact/test"
    roles: [Member]
  - path: "/api/v1/wildcard/*"
    roles: [OrgAdmin]
`;

    it('Layer 1: OpenAPI operation annotations take precedence over matrix routes and defaults', () => {
      const policy = parseAuthPolicy(basePolicyYaml);
      const endpoints = [
        {
          path: '/api/v1/exact/test',
          rawPath: '/api/v1/exact/test',
          method: 'GET',
          requiredRoles: ['SuperAdmin'], // Explicit OpenAPI annotation
          isAnonymous: false,
          pathParameters: [],
        },
      ];

      const report = reconcile(endpoints, policy);
      assert.equal(report.contracts[0].ruleSource, RULE_SOURCES.OPENAPI_ANNOTATION);
      assert.deepEqual(report.contracts[0].requiredRoles, ['SuperAdmin']);
    });

    it('Layer 2: Exact route match takes precedence over glob and method defaults', () => {
      const policy = parseAuthPolicy(basePolicyYaml);
      const endpoints = [
        {
          path: '/api/v1/exact/test',
          rawPath: '/api/v1/exact/test',
          method: 'DELETE', // Method default is OrgAdmin, but exact route specifies Member
          requiredRoles: [],
          isAnonymous: false,
          pathParameters: [],
        },
      ];

      const report = reconcile(endpoints, policy);
      assert.equal(report.contracts[0].ruleSource, RULE_SOURCES.MATRIX_EXACT);
      assert.deepEqual(report.contracts[0].requiredRoles, ['Member']);
    });

    it('Layer 3: Glob route match takes precedence over method and global defaults', () => {
      const policy = parseAuthPolicy(basePolicyYaml);
      const endpoints = [
        {
          path: '/api/v1/wildcard/anything',
          rawPath: '/api/v1/wildcard/anything',
          method: 'GET', // Method default not defined for GET, global default is Viewer
          requiredRoles: [],
          isAnonymous: false,
          pathParameters: [],
        },
      ];

      const report = reconcile(endpoints, policy);
      assert.equal(report.contracts[0].ruleSource, RULE_SOURCES.MATRIX_GLOB);
      assert.deepEqual(report.contracts[0].requiredRoles, ['OrgAdmin']);
    });

    it('Layer 4: Method default takes precedence over global default', () => {
      const policy = parseAuthPolicy(basePolicyYaml);
      const endpoints = [
        {
          path: '/api/v1/unmapped/item',
          rawPath: '/api/v1/unmapped/item',
          method: 'DELETE', // Method default specifies OrgAdmin
          requiredRoles: [],
          isAnonymous: false,
          pathParameters: [],
        },
      ];

      const report = reconcile(endpoints, policy);
      assert.equal(report.contracts[0].ruleSource, RULE_SOURCES.MATRIX_METHOD_DEFAULT);
      assert.deepEqual(report.contracts[0].requiredRoles, ['OrgAdmin']);
    });

    it('Layer 5: Global default role applies when route and method defaults are absent', () => {
      const policy = parseAuthPolicy(basePolicyYaml);
      const endpoints = [
        {
          path: '/api/v1/unmapped/item',
          rawPath: '/api/v1/unmapped/item',
          method: 'PATCH', // No method default for PATCH
          requiredRoles: [],
          isAnonymous: false,
          pathParameters: [],
        },
      ];

      const report = reconcile(endpoints, policy);
      assert.equal(report.contracts[0].ruleSource, RULE_SOURCES.MATRIX_GLOBAL_DEFAULT);
      assert.deepEqual(report.contracts[0].requiredRoles, ['Viewer']);
    });

    it('Zero-trust fallback denies unmapped route when no default role exists', () => {
      const zeroTrustPolicy = parseAuthPolicy(`
version: "1"
roles:
  - Admin
defaults:
  unauthenticated_access: deny
`);
      const endpoints = [
        {
          path: '/api/v1/orphan',
          method: 'GET',
          requiredRoles: [],
          isAnonymous: false,
          pathParameters: [],
        },
      ];

      const report = reconcile(endpoints, zeroTrustPolicy);
      assert.equal(report.contracts[0].ruleSource, RULE_SOURCES.UNMAPPED_DENY);
      assert.equal(report.contracts[0].isAnonymous, false);
      assert.deepEqual(report.contracts[0].requiredRoles, []);
      assert.ok(report.warnings.length > 0);
      assert.match(report.warnings[0], /zero-trust deny/);
    });

    it('preferPolicyOverSpec option allows matrix routes to override OpenAPI annotations', () => {
      const policy = parseAuthPolicy(basePolicyYaml);
      const endpoints = [
        {
          path: '/api/v1/exact/test',
          rawPath: '/api/v1/exact/test',
          method: 'GET',
          requiredRoles: ['SuperAdmin'], // OpenAPI says SuperAdmin
          isAnonymous: false,
          pathParameters: [],
        },
      ];

      const report = reconcile(endpoints, policy, { preferPolicyOverSpec: true });
      assert.equal(report.contracts[0].ruleSource, RULE_SOURCES.MATRIX_EXACT);
      assert.deepEqual(report.contracts[0].requiredRoles, ['Member']); // Policy route says Member
    });
  });

  describe('Diagnostics and Warnings', () => {
    it('generates a warning when OpenAPI operation references an undeclared role', () => {
      const policy = parseAuthPolicy(`
version: "1"
roles:
  - Admin
`);
      const endpoints = [
        {
          path: '/api/v1/billing',
          method: 'GET',
          requiredRoles: ['BillingManager'], // Undeclared in policy
          isAnonymous: false,
          pathParameters: [],
        },
      ];

      const report = reconcile(endpoints, policy);
      assert.equal(report.warnings.length, 1);
      assert.match(
        report.warnings[0],
        /requires role "BillingManager" which is not defined in the authorization policy/
      );
    });
  });

  describe('Error Handling', () => {
    it('throws ReconciliationError if endpoints is not an array', () => {
      const policy = parseAuthPolicy('version: "1"\nroles: [Admin]');
      assert.throws(
        () => reconcile(null, policy),
        (err) => {
          assert.ok(err instanceof ReconciliationError);
          return true;
        }
      );
    });

    it('throws ReconciliationError if authPolicy is omitted', () => {
      assert.throws(
        () => reconcile([], null),
        (err) => {
          assert.ok(err instanceof ReconciliationError);
          return true;
        }
      );
    });

    it('accepts raw YAML string as second argument', () => {
      const yamlStr = 'version: "1"\nroles: [Admin]';
      const report = reconcile([], yamlStr);
      assert.equal(report.contracts.length, 0);
    });
  });
});


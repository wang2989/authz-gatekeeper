import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  generateTestMatrix,
  calculateExpectedStatus,
  TEST_CATEGORIES,
  interpolatePath,
} from '../../src/matrix/planner.js';
import {
  generateTestMatrix as indexGenerateTestMatrix,
  calculateExpectedStatus as indexCalculateExpectedStatus,
  TEST_CATEGORIES as indexTEST_CATEGORIES,
  interpolatePath as indexInterpolatePath,
} from '../../src/index.js';
import { loadOpenApiSpec } from '../../src/parser/openapi-loader.js';
import { extractEndpoints } from '../../src/parser/openapi-extractor.js';
import { loadAuthPolicy } from '../../src/parser/policy-parser.js';
import { reconcile } from '../../src/parser/reconciler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const FIXTURES_DIR = join(__dirname, '..', 'fixtures');

describe('Permutation Matrix Planner (src/matrix/planner.js)', () => {
  describe('Package Exports from src/index.js', () => {
    it('re-exports all matrix planner entities from src/index.js', () => {
      assert.equal(typeof indexGenerateTestMatrix, 'function');
      assert.equal(typeof indexCalculateExpectedStatus, 'function');
      assert.equal(typeof indexInterpolatePath, 'function');
      assert.equal(indexTEST_CATEGORIES, TEST_CATEGORIES);
      assert.equal(indexGenerateTestMatrix, generateTestMatrix);
      assert.equal(indexCalculateExpectedStatus, calculateExpectedStatus);
      assert.equal(indexInterpolatePath, interpolatePath);
    });
  });

  describe('TEST_CATEGORIES Constants', () => {
    it('exports frozen object with all 4 required test categories', () => {
      assert.ok(Object.isFrozen(TEST_CATEGORIES));
      assert.deepEqual(TEST_CATEGORIES, {
        INTRA_TENANT_ALLOW: 'intra-tenant-allow',
        INTRA_TENANT_DENY: 'intra-tenant-deny',
        CROSS_TENANT_ATTACK: 'cross-tenant-attack',
        ANONYMOUS_BASELINE: 'anonymous-baseline',
      });
    });
  });

  describe('interpolatePath(pathPattern, paramFixtures)', () => {
    it('interpolates path parameters with matching fixture values', () => {
      const result = interpolatePath('/api/v1/{tenant_id}/projects/{project_id}', {
        tenant_id: 'acme-corp',
        project_id: 'proj-999',
      });
      assert.equal(result, '/api/v1/acme-corp/projects/proj-999');
    });

    it('falls back to mock-{paramName} when a fixture is missing', () => {
      const result = interpolatePath('/api/v1/{tenant_id}/items/{item_id}', {
        tenant_id: 'tenant-alpha',
      });
      assert.equal(result, '/api/v1/tenant-alpha/items/mock-item_id');
    });

    it('falls back to mock-{paramName} for all parameters when fixtures is empty or omitted', () => {
      assert.equal(
        interpolatePath('/api/v1/{tenant_id}/users/{user_id}'),
        '/api/v1/mock-tenant_id/users/mock-user_id'
      );
      assert.equal(
        interpolatePath('/api/v1/{tenant_id}/users/{user_id}', {}),
        '/api/v1/mock-tenant_id/users/mock-user_id'
      );
    });

    it('preserves query strings, hash fragments, and trailing slashes', () => {
      const result = interpolatePath('/api/v1/{tenant_id}/status/?verbose=true&sort=desc#section', {
        tenant_id: 'tenant-alpha',
      });
      assert.equal(result, '/api/v1/tenant-alpha/status/?verbose=true&sort=desc#section');
    });

    it('handles whitespace inside braces gracefully', () => {
      const result = interpolatePath('/api/v1/{ tenant_id }/data', {
        tenant_id: 'tenant-alpha',
      });
      assert.equal(result, '/api/v1/tenant-alpha/data');
    });

    it('returns empty string when pathPattern is not a string', () => {
      assert.equal(interpolatePath(null), '');
      assert.equal(interpolatePath(undefined), '');
      assert.equal(interpolatePath(123), '');
    });
  });

  describe('calculateExpectedStatus(contract, persona, testCategory)', () => {
    describe('INTRA_TENANT_ALLOW', () => {
      it('returns 201 for POST operations', () => {
        const contract = { method: 'POST' };
        assert.equal(calculateExpectedStatus(contract, null, TEST_CATEGORIES.INTRA_TENANT_ALLOW), 201);
        assert.equal(calculateExpectedStatus({ method: 'post' }, null, TEST_CATEGORIES.INTRA_TENANT_ALLOW), 201);
      });

      it('returns 204 for DELETE operations', () => {
        const contract = { method: 'DELETE' };
        assert.equal(calculateExpectedStatus(contract, null, TEST_CATEGORIES.INTRA_TENANT_ALLOW), 204);
        assert.equal(calculateExpectedStatus({ method: 'delete' }, null, TEST_CATEGORIES.INTRA_TENANT_ALLOW), 204);
      });

      it('returns 200 for GET, PUT, PATCH, and HEAD operations', () => {
        assert.equal(calculateExpectedStatus({ method: 'GET' }, null, TEST_CATEGORIES.INTRA_TENANT_ALLOW), 200);
        assert.equal(calculateExpectedStatus({ method: 'PUT' }, null, TEST_CATEGORIES.INTRA_TENANT_ALLOW), 200);
        assert.equal(calculateExpectedStatus({ method: 'PATCH' }, null, TEST_CATEGORIES.INTRA_TENANT_ALLOW), 200);
        assert.equal(calculateExpectedStatus({ method: 'HEAD' }, null, TEST_CATEGORIES.INTRA_TENANT_ALLOW), 200);
      });
    });

    describe('INTRA_TENANT_DENY', () => {
      it('returns 403 for all HTTP methods', () => {
        for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) {
          assert.equal(
            calculateExpectedStatus({ method }, null, TEST_CATEGORIES.INTRA_TENANT_DENY),
            403
          );
        }
      });
    });

    describe('CROSS_TENANT_ATTACK', () => {
      it('returns 403 for all HTTP methods', () => {
        for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) {
          assert.equal(
            calculateExpectedStatus({ method }, null, TEST_CATEGORIES.CROSS_TENANT_ATTACK),
            403
          );
        }
      });
    });

    describe('ANONYMOUS_BASELINE', () => {
      it('returns 200 (or 201 for POST, 204 for DELETE) when contract is anonymous', () => {
        assert.equal(
          calculateExpectedStatus({ method: 'GET', isAnonymous: true }, null, TEST_CATEGORIES.ANONYMOUS_BASELINE),
          200
        );
        assert.equal(
          calculateExpectedStatus({ method: 'POST', isAnonymous: true }, null, TEST_CATEGORIES.ANONYMOUS_BASELINE),
          201
        );
        assert.equal(
          calculateExpectedStatus({ method: 'DELETE', isAnonymous: true }, null, TEST_CATEGORIES.ANONYMOUS_BASELINE),
          204
        );
      });

      it('returns 401 when contract is protected (!isAnonymous)', () => {
        for (const method of ['GET', 'POST', 'PUT', 'DELETE']) {
          assert.equal(
            calculateExpectedStatus({ method, isAnonymous: false }, null, TEST_CATEGORIES.ANONYMOUS_BASELINE),
            401
          );
        }
      });
    });
  });

  describe('generateTestMatrix - Validation & Tenant ID Resolution', () => {
    it('throws TypeError if contractsOrReport is not an array or does not contain contracts array', () => {
      assert.throws(() => generateTestMatrix(null), {
        name: 'TypeError',
        message: /contractsOrReport must be an array of contracts or an object containing a contracts array/,
      });
      assert.throws(() => generateTestMatrix(undefined), { name: 'TypeError' });
      assert.throws(() => generateTestMatrix(123), { name: 'TypeError' });
      assert.throws(() => generateTestMatrix('invalid'), { name: 'TypeError' });
      assert.throws(() => generateTestMatrix({}), { name: 'TypeError' });
      assert.throws(() => generateTestMatrix({ contracts: 'not-an-array' }), { name: 'TypeError' });
    });

    it('resolves default primary and secondary tenant IDs when tenantConfig is omitted', () => {
      const contract = {
        path: '/api/{tenant_id}/test',
        method: 'GET',
        isAnonymous: false,
        authorizedRoles: ['Admin'],
        unauthorizedRoles: [],
        hasTenantBoundary: true,
        tenantParameter: 'tenant_id',
        fixtures: { primary: { tenant_id: 'tenant-alpha' } },
      };

      const matrix = generateTestMatrix([contract]);
      const allowVector = matrix.find((v) => v.category === TEST_CATEGORIES.INTRA_TENANT_ALLOW);
      const attackVector = matrix.find((v) => v.category === TEST_CATEGORIES.CROSS_TENANT_ATTACK);

      assert.equal(allowVector.persona.tenantId, 'tenant-alpha');
      assert.equal(allowVector.persona.userId, 'user-tenant-alpha-Admin');
      assert.equal(allowVector.targetTenant, 'tenant-alpha');

      assert.equal(attackVector.persona.tenantId, 'tenant-beta');
      assert.equal(attackVector.persona.userId, 'attacker-tenant-beta-Admin');
      assert.equal(attackVector.targetTenant, 'tenant-alpha');
      assert.equal(attackVector.isCrossTenant, true);
    });

    it('resolves custom tenant IDs from tenantConfig.fixtures', () => {
      const contract = {
        path: '/api/{tenant_id}/test',
        method: 'GET',
        isAnonymous: false,
        authorizedRoles: ['Admin'],
        unauthorizedRoles: [],
        hasTenantBoundary: true,
        tenantParameter: 'tenant_id',
      };

      const tenantConfig = {
        fixtures: {
          primary: { id: 'custom-org-1' },
          secondary: { id: 'custom-org-2' },
        },
      };

      const matrix = generateTestMatrix([contract], tenantConfig);
      const allowVector = matrix.find((v) => v.category === TEST_CATEGORIES.INTRA_TENANT_ALLOW);
      const attackVector = matrix.find((v) => v.category === TEST_CATEGORIES.CROSS_TENANT_ATTACK);

      assert.equal(allowVector.persona.tenantId, 'custom-org-1');
      assert.equal(allowVector.persona.userId, 'user-custom-org-1-Admin');
      assert.equal(allowVector.targetTenant, 'custom-org-1');
      assert.equal(allowVector.path, '/api/custom-org-1/test');

      assert.equal(attackVector.persona.tenantId, 'custom-org-2');
      assert.equal(attackVector.persona.userId, 'attacker-custom-org-2-Admin');
      assert.equal(attackVector.targetTenant, 'custom-org-1');
      assert.equal(attackVector.path, '/api/custom-org-1/test');
    });

    it('resolves custom tenant IDs from tenantConfig.primaryTenantId and secondaryTenantId shorthand', () => {
      const contract = {
        path: '/api/{tenant_id}/test',
        method: 'GET',
        isAnonymous: false,
        authorizedRoles: ['Admin'],
        unauthorizedRoles: [],
        hasTenantBoundary: true,
        tenantParameter: 'tenant_id',
      };

      const matrix = generateTestMatrix([contract], {
        primaryTenantId: 'corp-a',
        secondaryTenantId: 'corp-b',
      });

      const allowVector = matrix.find((v) => v.category === TEST_CATEGORIES.INTRA_TENANT_ALLOW);
      const attackVector = matrix.find((v) => v.category === TEST_CATEGORIES.CROSS_TENANT_ATTACK);

      assert.equal(allowVector.persona.tenantId, 'corp-a');
      assert.equal(attackVector.persona.tenantId, 'corp-b');
    });
  });

  describe('generateTestMatrix - Full Reconciled Specification Permutation', () => {
    async function loadTestReport() {
      const spec = await loadOpenApiSpec(join(FIXTURES_DIR, 'openapi.fixture.yaml'));
      const endpoints = extractEndpoints(spec);
      const policy = await loadAuthPolicy(join(FIXTURES_DIR, 'auth-matrix.fixture.yaml'));
      return reconcile(endpoints, policy);
    }

    it('generates vectors with valid schema and augmented summary properties', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report);

      // Verify array augmentation
      assert.ok(Array.isArray(matrix));
      assert.equal(matrix.vectors, matrix);
      assert.ok(matrix.summary);
      assert.equal(matrix.summary.totalVectors, matrix.length);
      assert.ok(matrix.length > 0);

      // Verify summary structure
      assert.equal(
        matrix.summary.byCategory[TEST_CATEGORIES.INTRA_TENANT_ALLOW] +
          matrix.summary.byCategory[TEST_CATEGORIES.INTRA_TENANT_DENY] +
          matrix.summary.byCategory[TEST_CATEGORIES.CROSS_TENANT_ATTACK] +
          matrix.summary.byCategory[TEST_CATEGORIES.ANONYMOUS_BASELINE],
        matrix.length
      );
      assert.equal(matrix.summary.routesCovered, 4);

      // Verify every vector adheres to strict schema
      for (const vector of matrix) {
        assert.equal(typeof vector.id, 'string');
        assert.ok(vector.id.length > 0);
        assert.ok(Object.values(TEST_CATEGORIES).includes(vector.category));
        assert.ok(['GET', 'POST', 'PUT', 'DELETE'].includes(vector.method));
        assert.equal(typeof vector.route, 'string');
        assert.equal(typeof vector.path, 'string');
        assert.ok(!vector.path.includes('{'), `Interpolated path must not contain unreplaced braces: ${vector.path}`);

        assert.equal(typeof vector.persona, 'object');
        assert.equal(typeof vector.persona.isAnonymous, 'boolean');
        if (vector.persona.isAnonymous) {
          assert.equal(vector.persona.role, null);
          assert.equal(vector.persona.tenantId, null);
          assert.equal(vector.persona.userId, null);
        } else {
          assert.equal(typeof vector.persona.role, 'string');
          assert.equal(typeof vector.persona.tenantId, 'string');
          assert.equal(typeof vector.persona.userId, 'string');
        }

        assert.equal(vector.targetTenant, 'tenant-alpha');
        assert.equal(typeof vector.isCrossTenant, 'boolean');
        assert.equal(typeof vector.expectedStatus, 'number');
        assert.ok(Array.isArray(vector.expectedStatusCodes));
        assert.ok(vector.expectedStatusCodes.includes(vector.expectedStatus));
        assert.equal(typeof vector.description, 'string');

        // Contract sub-object
        assert.ok(vector.contract);
        assert.equal(typeof vector.contract.path, 'string');
        assert.equal(typeof vector.contract.method, 'string');
        assert.equal(typeof vector.contract.isAnonymous, 'boolean');
        assert.ok(Array.isArray(vector.contract.requiredRoles));
        assert.equal(typeof vector.contract.hasTenantBoundary, 'boolean');

        // Parameters & body schema
        assert.ok(Array.isArray(vector.parameters));
        assert.equal(typeof vector.hasRequestBody, 'boolean');
      }
    });

    it('verifies public endpoint /health produces only ANONYMOUS_BASELINE', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report);

      const healthVectors = matrix.filter((v) => v.route === '/health');
      assert.equal(healthVectors.length, 1);

      const healthVector = healthVectors[0];
      assert.equal(healthVector.category, TEST_CATEGORIES.ANONYMOUS_BASELINE);
      assert.equal(healthVector.method, 'GET');
      assert.equal(healthVector.path, '/health');
      assert.equal(healthVector.persona.isAnonymous, true);
      assert.equal(healthVector.expectedStatus, 200);
      assert.deepEqual(healthVector.expectedStatusCodes, [200, 201, 202, 204]);
      assert.equal(healthVector.isCrossTenant, false);
    });

    it('verifies protected endpoint POST /api/v1/{tenant_id}/projects permutations', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report);

      const postProjects = matrix.filter(
        (v) => v.route === '/api/v1/{tenant_id}/projects' && v.method === 'POST'
      );

      // Authorized roles: OrgAdmin, SuperAdmin
      const allowVectors = postProjects.filter((v) => v.category === TEST_CATEGORIES.INTRA_TENANT_ALLOW);
      assert.equal(allowVectors.length, 2);
      const allowRoles = allowVectors.map((v) => v.persona.role).sort();
      assert.deepEqual(allowRoles, ['OrgAdmin', 'SuperAdmin']);
      for (const v of allowVectors) {
        assert.equal(v.expectedStatus, 201);
        assert.deepEqual(v.expectedStatusCodes, [200, 201, 202, 204]);
        assert.equal(v.path, '/api/v1/tenant-alpha/projects');
        assert.equal(v.persona.tenantId, 'tenant-alpha');
        assert.equal(v.isCrossTenant, false);
      }

      // Unauthorized roles: Viewer, Member
      const denyVectors = postProjects.filter((v) => v.category === TEST_CATEGORIES.INTRA_TENANT_DENY);
      assert.equal(denyVectors.length, 2);
      const denyRoles = denyVectors.map((v) => v.persona.role).sort();
      assert.deepEqual(denyRoles, ['Member', 'Viewer']);
      for (const v of denyVectors) {
        assert.equal(v.expectedStatus, 403);
        assert.deepEqual(v.expectedStatusCodes, [403]);
        assert.equal(v.path, '/api/v1/tenant-alpha/projects');
        assert.equal(v.persona.tenantId, 'tenant-alpha');
        assert.equal(v.isCrossTenant, false);
      }

      // Cross-tenant attack vectors: OrgAdmin, SuperAdmin targeting tenant-alpha with tenant-beta credentials
      const attackVectors = postProjects.filter((v) => v.category === TEST_CATEGORIES.CROSS_TENANT_ATTACK);
      assert.equal(attackVectors.length, 2);
      for (const v of attackVectors) {
        assert.equal(v.expectedStatus, 403);
        assert.deepEqual(v.expectedStatusCodes, [403, 404]);
        assert.equal(v.targetTenant, 'tenant-alpha');
        assert.equal(v.persona.tenantId, 'tenant-beta');
        assert.equal(v.isCrossTenant, true);
        assert.equal(v.path, '/api/v1/tenant-alpha/projects');
        assert.ok(v.persona.userId.startsWith('attacker-tenant-beta-'));
      }

      // Anonymous baseline: protected route rejected with 401
      const anonVectors = postProjects.filter((v) => v.category === TEST_CATEGORIES.ANONYMOUS_BASELINE);
      assert.equal(anonVectors.length, 1);
      assert.equal(anonVectors[0].persona.isAnonymous, true);
      assert.equal(anonVectors[0].expectedStatus, 401);
      assert.deepEqual(anonVectors[0].expectedStatusCodes, [401, 403]);
    });

    it('verifies DELETE /api/v1/{tenant_id}/projects/{project_id} expected status 204', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report);

      const deleteVectors = matrix.filter(
        (v) => v.route === '/api/v1/{tenant_id}/projects/{project_id}' && v.method === 'DELETE'
      );

      const allowVectors = deleteVectors.filter((v) => v.category === TEST_CATEGORIES.INTRA_TENANT_ALLOW);
      assert.ok(allowVectors.length > 0);
      for (const v of allowVectors) {
        assert.equal(v.expectedStatus, 204);
        assert.deepEqual(v.expectedStatusCodes, [200, 202, 204]);
      }
    });
  });

  describe('generateTestMatrix - Options & Filtering', () => {
    async function loadTestReport() {
      const spec = await loadOpenApiSpec(join(FIXTURES_DIR, 'openapi.fixture.yaml'));
      const endpoints = extractEndpoints(spec);
      const policy = await loadAuthPolicy(join(FIXTURES_DIR, 'auth-matrix.fixture.yaml'));
      return reconcile(endpoints, policy);
    }

    it('filters out anonymous baseline when skipAnonymous: true', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report, {}, { skipAnonymous: true });

      const anonVectors = matrix.filter((v) => v.category === TEST_CATEGORIES.ANONYMOUS_BASELINE);
      assert.equal(anonVectors.length, 0);
      assert.equal(matrix.summary.byCategory[TEST_CATEGORIES.ANONYMOUS_BASELINE], 0);
    });

    it('filters out cross-tenant attacks when skipCrossTenant: true', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report, {}, { skipCrossTenant: true });

      const attackVectors = matrix.filter((v) => v.category === TEST_CATEGORIES.CROSS_TENANT_ATTACK);
      assert.equal(attackVectors.length, 0);
      assert.equal(matrix.summary.byCategory[TEST_CATEGORIES.CROSS_TENANT_ATTACK], 0);
    });

    it('filters by categories array', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report, {}, {
        categories: [TEST_CATEGORIES.INTRA_TENANT_ALLOW],
      });

      assert.ok(matrix.length > 0);
      for (const v of matrix) {
        assert.equal(v.category, TEST_CATEGORIES.INTRA_TENANT_ALLOW);
      }
      assert.equal(matrix.summary.byCategory[TEST_CATEGORIES.INTRA_TENANT_DENY], 0);
      assert.equal(matrix.summary.byCategory[TEST_CATEGORIES.CROSS_TENANT_ATTACK], 0);
      assert.equal(matrix.summary.byCategory[TEST_CATEGORIES.ANONYMOUS_BASELINE], 0);
    });

    it('filters by roles array', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report, {}, {
        roles: ['SuperAdmin'],
      });

      assert.ok(matrix.length > 0);
      for (const v of matrix) {
        assert.equal(v.persona.role, 'SuperAdmin');
      }
    });

    it('filters by methods array', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report, {}, {
        methods: ['delete'],
      });

      assert.ok(matrix.length > 0);
      for (const v of matrix) {
        assert.equal(v.method, 'DELETE');
      }
      assert.deepEqual(Object.keys(matrix.summary.byMethod), ['DELETE']);
    });

    it('supports options passed directly in 2nd argument position', async () => {
      const report = await loadTestReport();
      const matrix = generateTestMatrix(report, { skipAnonymous: true, skipCrossTenant: true });

      assert.equal(matrix.summary.byCategory[TEST_CATEGORIES.ANONYMOUS_BASELINE], 0);
      assert.equal(matrix.summary.byCategory[TEST_CATEGORIES.CROSS_TENANT_ATTACK], 0);
      assert.ok(matrix.summary.byCategory[TEST_CATEGORIES.INTRA_TENANT_ALLOW] > 0);
      assert.ok(matrix.summary.byCategory[TEST_CATEGORIES.INTRA_TENANT_DENY] > 0);
    });
  });
});


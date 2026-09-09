import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { loadOpenApiSpec } from '../../src/parser/openapi-loader.js';
import {
  normalizePath,
  extractPathVariables,
  normalizeParameters,
  extractRoles,
  extractSecurity,
  extractRequestBodySchema,
  extractEndpoints,
} from '../../src/parser/openapi-extractor.js';

describe('OpenAPI Route & Security Annotation Extractor (src/parser/openapi-extractor.js)', () => {
  describe('Path Normalization & Variable Extraction', () => {
    it('normalizes Express-style :param variables to OpenAPI {param} format', () => {
      assert.equal(
        normalizePath('/api/v1/:tenant_id/users/:user_id/profile'),
        '/api/v1/{tenant_id}/users/{user_id}/profile'
      );
    });

    it('cleans redundant consecutive slashes and strips trailing slashes', () => {
      assert.equal(normalizePath('///api//v1///projects/'), '/api/v1/projects');
      assert.equal(normalizePath('/'), '/');
    });

    it('extracts all template path variables correctly', () => {
      const vars = extractPathVariables('/api/v1/{tenant_id}/projects/{project_id}/tasks/{taskId}');
      assert.deepEqual(vars, ['tenant_id', 'project_id', 'taskId']);

      const noVars = extractPathVariables('/health');
      assert.deepEqual(noVars, []);
    });
  });

  describe('Parameter Normalization & Merging', () => {
    it('overrides path-level parameters with operation-level parameters sharing the same name and location', () => {
      const pathLevel = [
        { name: 'tenant_id', in: 'path', description: 'Path level tenant' },
        { name: 'limit', in: 'query', required: false, description: 'Default limit 10' },
      ];
      const opLevel = [
        { name: 'limit', in: 'query', required: true, description: 'Operation specific limit 50' },
        { name: 'offset', in: 'query', required: false },
      ];

      const merged = normalizeParameters([...pathLevel, ...opLevel]);

      assert.equal(merged.length, 3);
      const limitParam = merged.find((p) => p.name === 'limit');
      assert.equal(limitParam.required, true);
      assert.equal(limitParam.description, 'Operation specific limit 50');

      const tenantParam = merged.find((p) => p.name === 'tenant_id');
      assert.equal(tenantParam.required, true); // Path parameters are always required
    });
  });

  describe('Role Annotation Extraction', () => {
    it('extracts roles from x-required-role as array, string, or comma-separated list', () => {
      assert.deepEqual(extractRoles({ 'x-required-role': ['OrgAdmin', 'SuperAdmin'] }), [
        'OrgAdmin',
        'SuperAdmin',
      ]);

      assert.deepEqual(extractRoles({ 'x-required-role': 'OrgAdmin' }), ['OrgAdmin']);

      assert.deepEqual(extractRoles({ 'x-roles': 'Viewer, Member, OrgAdmin' }), [
        'Viewer',
        'Member',
        'OrgAdmin',
      ]);

      assert.deepEqual(extractRoles({ 'x-role': 'Admin' }), ['Admin']);
      assert.deepEqual(extractRoles({}), []);
    });
  });

  describe('Security & Anonymous Evaluation', () => {
    it('identifies operation with security: [] as anonymous/public', () => {
      const { isAnonymous } = extractSecurity({ security: [] }, [{ bearerAuth: [] }]);
      assert.equal(isAnonymous, true);
    });

    it('identifies operation with empty Security Requirement Object [{}] as anonymous/public', () => {
      const { isAnonymous, securityRequirements } = extractSecurity({ security: [{}] }, [{ bearerAuth: [] }]);
      assert.equal(isAnonymous, true);
      assert.deepEqual(securityRequirements, [{}]);
    });

    it('identifies operation with optional authentication [{ bearerAuth: [] }, {}] as anonymous', () => {
      const { isAnonymous, securityRequirements } = extractSecurity(
        { security: [{ bearerAuth: [] }, {}] },
        [{ bearerAuth: [] }]
      );
      assert.equal(isAnonymous, true);
      assert.deepEqual(securityRequirements, [{ bearerAuth: [] }, {}]);
    });

    it('identifies operation with x-allow-anonymous: true as anonymous', () => {
      const { isAnonymous } = extractSecurity(
        { 'x-allow-anonymous': true, security: [{ bearerAuth: [] }] },
        [{ bearerAuth: [] }]
      );
      assert.equal(isAnonymous, true);
    });

    it('inherits root security requirements when operation security is omitted', () => {
      const { isAnonymous, securityRequirements, requiredScopes } = extractSecurity(
        {},
        [{ oauth2: ['read:projects', 'write:projects'] }]
      );
      assert.equal(isAnonymous, false);
      assert.deepEqual(securityRequirements, [{ oauth2: ['read:projects', 'write:projects'] }]);
      assert.deepEqual(requiredScopes, ['read:projects', 'write:projects']);
    });

    it('identifies inherited root security with optional auth [..., {}] as anonymous', () => {
      const { isAnonymous, securityRequirements } = extractSecurity(
        {},
        [{ bearerAuth: [] }, {}]
      );
      assert.equal(isAnonymous, true);
      assert.deepEqual(securityRequirements, [{ bearerAuth: [] }, {}]);
    });

    it('identifies inherited root security with [{}] as anonymous', () => {
      const { isAnonymous, securityRequirements } = extractSecurity({}, [{}]);
      assert.equal(isAnonymous, true);
      assert.deepEqual(securityRequirements, [{}]);
    });

    it('allows operation to override root security with strictly protected requirement', () => {
      const { isAnonymous, securityRequirements } = extractSecurity(
        { security: [{ bearerAuth: [] }] },
        [{ bearerAuth: [] }, {}]
      );
      assert.equal(isAnonymous, false);
      assert.deepEqual(securityRequirements, [{ bearerAuth: [] }]);
    });

    it('defaults to anonymous if neither operation nor root specifies security', () => {
      const { isAnonymous, securityRequirements } = extractSecurity({}, []);
      assert.equal(isAnonymous, true);
      assert.deepEqual(securityRequirements, []);
    });
  });

  describe('Request Body Schema Extraction', () => {
    it('extracts application/json request body schema', () => {
      const op = {
        requestBody: {
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ProjectCreate' },
            },
          },
        },
      };

      const schema = extractRequestBodySchema(op);
      assert.deepEqual(schema, { $ref: '#/components/schemas/ProjectCreate' });
    });

    it('returns null when requestBody is missing', () => {
      assert.equal(extractRequestBodySchema({}), null);
    });
  });

  describe('Comprehensive extractEndpoints Integration', () => {
    it('extracts all 7 endpoints from the standard openapi.fixture.json', async () => {
      const spec = await loadOpenApiSpec('test/fixtures/openapi.fixture.json');
      const endpoints = extractEndpoints(spec);

      assert.equal(endpoints.length, 7);

      // 1. GET /health
      const healthEndpoint = endpoints.find((e) => e.path === '/health' && e.method === 'GET');
      assert.ok(healthEndpoint);
      assert.equal(healthEndpoint.isAnonymous, true);
      assert.equal(healthEndpoint.hasRequestBody, false);

      // 2. GET /api/v1/{tenant_id}/projects
      const listProjects = endpoints.find(
        (e) => e.path === '/api/v1/{tenant_id}/projects' && e.method === 'GET'
      );
      assert.ok(listProjects);
      assert.equal(listProjects.isAnonymous, false);
      assert.deepEqual(listProjects.pathParameters, ['tenant_id']);
      assert.deepEqual(listProjects.requiredRoles, ['Viewer', 'Member', 'OrgAdmin', 'SuperAdmin']);

      // 3. POST /api/v1/{tenant_id}/projects
      const createProject = endpoints.find(
        (e) => e.path === '/api/v1/{tenant_id}/projects' && e.method === 'POST'
      );
      assert.ok(createProject);
      assert.equal(createProject.hasRequestBody, true);
      assert.deepEqual(createProject.requestBodySchema, {
        $ref: '#/components/schemas/ProjectCreate',
      });
      assert.deepEqual(createProject.requiredRoles, ['OrgAdmin', 'SuperAdmin']);

      // 4. GET /api/v1/{tenant_id}/projects/{project_id}
      const getProject = endpoints.find(
        (e) => e.path === '/api/v1/{tenant_id}/projects/{project_id}' && e.method === 'GET'
      );
      assert.ok(getProject);
      assert.deepEqual(getProject.pathParameters, ['tenant_id', 'project_id']);

      // 5. PUT /api/v1/{tenant_id}/projects/{project_id}
      const updateProject = endpoints.find(
        (e) => e.path === '/api/v1/{tenant_id}/projects/{project_id}' && e.method === 'PUT'
      );
      assert.ok(updateProject);
      assert.equal(updateProject.hasRequestBody, true);

      // 6. DELETE /api/v1/{tenant_id}/projects/{project_id}
      const deleteProject = endpoints.find(
        (e) => e.path === '/api/v1/{tenant_id}/projects/{project_id}' && e.method === 'DELETE'
      );
      assert.ok(deleteProject);
      assert.equal(deleteProject.method, 'DELETE');

      // 7. GET /api/v1/{tenant_id}/admin/settings
      const adminEndpoint = endpoints.find(
        (e) => e.path === '/api/v1/{tenant_id}/admin/settings' && e.method === 'GET'
      );
      assert.ok(adminEndpoint);
      assert.deepEqual(adminEndpoint.requiredRoles, ['SuperAdmin']);
    });

    it('extracts endpoints with identical parity from openapi.fixture.yaml', async () => {
      const spec = await loadOpenApiSpec('test/fixtures/openapi.fixture.yaml');
      const endpoints = extractEndpoints(spec);

      assert.equal(endpoints.length, 7);
      const deleteOp = endpoints.find((e) => e.method === 'DELETE');
      assert.ok(deleteOp);
      assert.deepEqual(deleteOp.pathParameters, ['tenant_id', 'project_id']);
    });

    it('returns empty array cleanly on minimal fixture with paths: {}', async () => {
      const spec = await loadOpenApiSpec('test/fixtures/openapi-minimal.json');
      const endpoints = extractEndpoints(spec);
      assert.deepEqual(endpoints, []);
    });

    it('safely ignores non-HTTP operation keys in path objects (e.g., summary, description, parameters)', () => {
      const mockSpec = {
        openapi: '3.0.0',
        info: { title: 'Mock', version: '1.0' },
        paths: {
          '/test': {
            summary: 'Path summary metadata',
            description: 'Path description metadata',
            parameters: [{ name: 'tenant_id', in: 'path' }],
            get: {
              summary: 'Actual operation',
              responses: { 200: { description: 'OK' } },
            },
          },
        },
      };

      const endpoints = extractEndpoints(mockSpec);
      assert.equal(endpoints.length, 1);
      assert.equal(endpoints[0].method, 'GET');
      assert.deepEqual(endpoints[0].pathParameters, ['tenant_id']);
    });
  });
});


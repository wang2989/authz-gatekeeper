import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  loadOpenApiSpec,
  parseSpecContent,
  validateOpenApiStructure,
  InvalidSpecError,
} from '../../src/parser/openapi-loader.js';

describe('OpenAPI Loader & Normalizer (src/parser/openapi-loader.js)', () => {
  let activeServers = [];

  afterEach(async () => {
    await Promise.all(
      activeServers.map(
        (server) =>
          new Promise((resolve) => {
            if (typeof server.closeAllConnections === 'function') {
              server.closeAllConnections();
            }
            server.close(() => resolve());
          })
      )
    );
    activeServers = [];
  });

  function startMockServer(handler) {
    return new Promise((resolve) => {
      const server = http.createServer(handler);
      server.listen(0, '127.0.0.1', () => {
        activeServers.push(server);
        const port = server.address().port;
        resolve({ server, port, url: `http://127.0.0.1:${port}` });
      });
    });
  }

  describe('Local File Ingestion', () => {
    it('loads a valid OpenAPI 3.0.3 JSON specification with required and optional fields', async () => {
      const spec = await loadOpenApiSpec('test/fixtures/openapi.fixture.json');

      assert.equal(spec.openapi, '3.0.3');
      assert.equal(spec.info.title, 'Multi-Tenant Authz Gateway API');
      assert.equal(spec.info.version, '1.0.0');
      assert.ok(spec.paths['/health']);
      assert.ok(spec.paths['/api/v1/{tenant_id}/projects']);
      assert.ok(spec.paths['/api/v1/{tenant_id}/projects/{project_id}']);
      assert.ok(spec.paths['/api/v1/{tenant_id}/admin/settings']);

      // Verify optional fields
      assert.equal(spec.servers[0].url, 'http://localhost:8000');
      assert.ok(spec.components.securitySchemes.bearerAuth);
      assert.equal(spec.components.securitySchemes.bearerAuth.scheme, 'bearer');
      assert.ok(spec.components.schemas.ProjectCreate);
      assert.deepEqual(spec.security, [{ bearerAuth: [] }]);
    });

    it('loads a valid OpenAPI 3.0.3 YAML specification with parity to JSON', async () => {
      const spec = await loadOpenApiSpec('test/fixtures/openapi.fixture.yaml');

      assert.equal(spec.openapi, '3.0.3');
      assert.equal(spec.info.title, 'Multi-Tenant Authz Gateway API');
      assert.ok(spec.paths['/health']);
      assert.ok(spec.paths['/api/v1/{tenant_id}/projects']);
      assert.ok(spec.components.securitySchemes.bearerAuth);
    });

    it('loads a minimal valid specification with strictly required fields', async () => {
      const spec = await loadOpenApiSpec('test/fixtures/openapi-minimal.json');

      assert.equal(spec.openapi, '3.0.3');
      assert.equal(spec.info.title, 'Minimal Required-Fields API');
      assert.equal(spec.info.version, '0.1.0');
      assert.deepEqual(spec.paths, {});
    });

    it('throws InvalidSpecError with exitCode 2 when local file does not exist', async () => {
      await assert.rejects(
        () => loadOpenApiSpec('test/fixtures/non-existent-file.json'),
        (err) => {
          assert.equal(err instanceof InvalidSpecError, true);
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.equal(err.exitCode, 2);
          assert.match(err.message, /file not found or unreadable/);
          return true;
        }
      );
    });
  });

  describe('Remote HTTP(S) Spec Ingestion', () => {
    it('fetches and parses an OpenAPI JSON specification from a remote HTTP URL', async () => {
      const { url } = await startMockServer((req, res) => {
        if (req.url === '/v3/api-docs') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              openapi: '3.0.1',
              info: { title: 'Remote API', version: '2.0.0' },
              paths: {
                '/remote/endpoint': {
                  get: { responses: { 200: { description: 'OK' } } },
                },
              },
            })
          );
        } else {
          res.writeHead(404);
          res.end();
        }
      });

      const spec = await loadOpenApiSpec(`${url}/v3/api-docs`);
      assert.equal(spec.openapi, '3.0.1');
      assert.equal(spec.info.title, 'Remote API');
      assert.ok(spec.paths['/remote/endpoint']);
    });

    it('throws InvalidSpecError when remote endpoint returns HTTP 404', async () => {
      const { url } = await startMockServer((req, res) => {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      });

      await assert.rejects(
        () => loadOpenApiSpec(`${url}/missing-spec.json`),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.equal(err.exitCode, 2);
          assert.match(err.message, /HTTP 404/);
          return true;
        }
      );
    });

    it('throws InvalidSpecError when remote server connection is refused', async () => {
      await assert.rejects(
        () => loadOpenApiSpec('http://127.0.0.1:59998/openapi.json'),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.equal(err.exitCode, 2);
          assert.match(err.message, /Failed to fetch remote OpenAPI specification/);
          return true;
        }
      );
    });
  });

  describe('Syntax & Format Parsing', () => {
    it('throws InvalidSpecError on malformed JSON syntax', async () => {
      await assert.rejects(
        () => loadOpenApiSpec('test/fixtures/invalid/malformed-syntax.json'),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.equal(err.exitCode, 2);
          assert.match(err.message, /Failed to parse OpenAPI specification as JSON or YAML/);
          return true;
        }
      );
    });

    it('throws InvalidSpecError on malformed YAML syntax', async () => {
      await assert.rejects(
        () => loadOpenApiSpec('test/fixtures/invalid/malformed-syntax.yaml'),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.equal(err.exitCode, 2);
          assert.match(err.message, /Failed to parse OpenAPI specification as JSON or YAML/);
          return true;
        }
      );
    });

    it('throws InvalidSpecError when raw input is empty', () => {
      assert.throws(
        () => parseSpecContent('   '),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.match(err.message, /content is empty/);
          return true;
        }
      );
    });
  });

  describe('Structural Validation', () => {
    it('throws InvalidSpecError when paths object is missing', async () => {
      await assert.rejects(
        () => loadOpenApiSpec('test/fixtures/invalid/missing-paths.json'),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.equal(err.exitCode, 2);
          assert.match(err.message, /missing required "paths" object/);
          return true;
        }
      );
    });

    it('throws InvalidSpecError on unsupported Swagger 1.2 version', async () => {
      await assert.rejects(
        () => loadOpenApiSpec('test/fixtures/invalid/unsupported-version.json'),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.equal(err.exitCode, 2);
          assert.match(err.message, /Unsupported Swagger version "1.2"/);
          return true;
        }
      );
    });

    it('throws InvalidSpecError when openapi version string is missing', () => {
      assert.throws(
        () => validateOpenApiStructure({ info: { title: 'Test', version: '1.0' }, paths: {} }),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.match(err.message, /missing "openapi" version declaration/);
          return true;
        }
      );
    });

    it('throws InvalidSpecError when info title or version is missing', () => {
      assert.throws(
        () => validateOpenApiStructure({ openapi: '3.0.0', info: { version: '1.0' }, paths: {} }),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.match(err.message, /"info.title" is required/);
          return true;
        }
      );

      assert.throws(
        () => validateOpenApiStructure({ openapi: '3.0.0', info: { title: 'Test' }, paths: {} }),
        (err) => {
          assert.equal(err.code, 'ERR_INVALID_SPEC');
          assert.match(err.message, /"info.version" is required/);
          return true;
        }
      );
    });

    it('rejects non-string or whitespace info.version values (numbers, booleans, arrays, objects)', () => {
      const invalidVersions = [
        1.0,
        100,
        true,
        false,
        ['1.0.0'],
        { major: 1, minor: 0 },
        '   ',
      ];

      for (const invalidVersion of invalidVersions) {
        assert.throws(
          () =>
            validateOpenApiStructure({
              openapi: '3.0.0',
              info: { title: 'Test API', version: invalidVersion },
              paths: {},
            }),
          (err) => {
            assert.equal(err.code, 'ERR_INVALID_SPEC');
            assert.match(err.message, /"info.version" is required and must be a non-empty string/);
            return true;
          },
          `Expected info.version value "${JSON.stringify(invalidVersion)}" to be rejected.`
        );
      }
    });

    it('accepts valid Swagger 2.0 specification', () => {
      const validSwagger2 = {
        swagger: '2.0',
        info: { title: 'Legacy Swagger API', version: '1.0' },
        paths: {},
      };
      const result = validateOpenApiStructure(validSwagger2, 'swagger.json');
      assert.equal(result.swagger, '2.0');
    });
  });
});


import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { parseCliArgs, getHelpText } from '../../src/cli/args.js';

describe('CLI Argument Parser (src/cli/args.js)', () => {
  it('parses all required long options correctly', () => {
    const args = [
      '--spec', './openapi.json',
      '--target', 'http://localhost:8000',
      '--jwt-secret', 'test-secret-key-123'
    ];

    const config = parseCliArgs(args, {});
    assert.equal(config.spec, './openapi.json');
    assert.equal(config.target, 'http://localhost:8000');
    assert.equal(config.jwtSecret, 'test-secret-key-123');
    assert.equal(config.outDir, './gatekeeper-out');
    assert.equal(config.healthPath, '/health');
    assert.equal(config.noProbe, false);
    assert.equal(config.allowValidationErrors, false);
    assert.equal(config.concurrency, 10);
    assert.equal(config.timeout, 5000);
  });

  it('parses short aliases correctly', () => {
    const args = [
      '-s', './spec.yaml',
      '-t', 'http://127.0.0.1:3000/',
      '--jwt-secret', 'my-secret',
      '-p', './matrix.yaml',
      '-o', './custom-artifacts',
      '-c', '25'
    ];

    const config = parseCliArgs(args, {});
    assert.equal(config.spec, './spec.yaml');
    assert.equal(config.target, 'http://127.0.0.1:3000'); // Strips trailing slash
    assert.equal(config.jwtSecret, 'my-secret');
    assert.equal(config.policy, './matrix.yaml');
    assert.equal(config.outDir, './custom-artifacts');
    assert.equal(config.concurrency, 25);
  });

  it('supports scan subcommand prefix', () => {
    const args = [
      'scan',
      '--spec', './spec.json',
      '--target', 'http://localhost:8000',
      '--jwt-secret', 'secret'
    ];

    const config = parseCliArgs(args, {});
    assert.equal(config.spec, './spec.json');
    assert.equal(config.target, 'http://localhost:8000');
  });

  it('falls back to environment variables when flags are omitted', () => {
    const env = {
      GATEKEEPER_SPEC_FILE: '/ci/openapi.json',
      GATEKEEPER_TARGET_URL: 'http://backend.internal:8080',
      GATEKEEPER_JWT_SECRET: 'env-super-secret',
      GATEKEEPER_POLICY_FILE: '/ci/auth-matrix.yaml',
      GATEKEEPER_OUT_DIR: '/ci/reports'
    };

    const config = parseCliArgs([], env);
    assert.equal(config.spec, '/ci/openapi.json');
    assert.equal(config.target, 'http://backend.internal:8080');
    assert.equal(config.jwtSecret, 'env-super-secret');
    assert.equal(config.policy, '/ci/auth-matrix.yaml');
    assert.equal(config.outDir, '/ci/reports');
  });

  it('prioritizes CLI flags over environment variables', () => {
    const env = {
      GATEKEEPER_SPEC_FILE: '/env/openapi.json',
      GATEKEEPER_TARGET_URL: 'http://env-target:8000',
      GATEKEEPER_JWT_SECRET: 'env-secret'
    };
    const args = [
      '--spec', '/cli/openapi.json',
      '--target', 'http://cli-target:9000',
      '--jwt-secret', 'cli-secret'
    ];

    const config = parseCliArgs(args, env);
    assert.equal(config.spec, '/cli/openapi.json');
    assert.equal(config.target, 'http://cli-target:9000');
    assert.equal(config.jwtSecret, 'cli-secret');
  });

  it('handles boolean flags: --no-probe and --allow-validation-errors', () => {
    const args = [
      '--spec', './spec.json',
      '--target', 'http://localhost:8000',
      '--jwt-secret', 'secret',
      '--no-probe',
      '--allow-validation-errors'
    ];

    const config = parseCliArgs(args, {});
    assert.equal(config.noProbe, true);
    assert.equal(config.allowValidationErrors, true);
  });

  it('throws descriptive error with exitCode 2 when required options are missing', () => {
    assert.throws(
      () => parseCliArgs([], {}),
      (err) => {
        assert.equal(err.code, 'ERR_MISSING_REQUIRED_CONFIG');
        assert.equal(err.exitCode, 2);
        assert.match(err.message, /Missing required configuration options/);
        assert.match(err.message, /--spec/);
        assert.match(err.message, /--target/);
        assert.match(err.message, /--jwt-secret/);
        return true;
      }
    );
  });

  it('throws error with exitCode 2 on invalid numeric concurrency or timeout', () => {
    assert.throws(
      () => parseCliArgs(['--spec', 's', '--target', 't', '--jwt-secret', 'k', '--concurrency', '0'], {}),
      (err) => {
        assert.equal(err.code, 'ERR_INVALID_CONFIG');
        assert.equal(err.exitCode, 2);
        return true;
      }
    );

    assert.throws(
      () => parseCliArgs(['--spec', 's', '--target', 't', '--jwt-secret', 'k', '--timeout', 'invalid'], {}),
      (err) => {
        assert.equal(err.code, 'ERR_INVALID_CONFIG');
        assert.equal(err.exitCode, 2);
        return true;
      }
    );
  });

  it('returns { help: true } on --help or -h without requiring other arguments', () => {
    const res1 = parseCliArgs(['--help'], {});
    assert.deepEqual(res1, { help: true });

    const res2 = parseCliArgs(['-h'], {});
    assert.deepEqual(res2, { help: true });

    const helpText = getHelpText();
    assert.match(helpText, /Usage:/);
    assert.match(helpText, /--spec/);
  });

  it('returns { version: true } on --version or -v without requiring other arguments', () => {
    const res1 = parseCliArgs(['--version'], {});
    assert.deepEqual(res1, { version: true });

    const res2 = parseCliArgs(['-v'], {});
    assert.deepEqual(res2, { version: true });
  });

  it('throws error on unrecognized CLI options', () => {
    assert.throws(
      () => parseCliArgs(['--unknown-option'], {}),
      (err) => {
        assert.equal(err.code, 'ERR_INVALID_ARGS');
        assert.equal(err.exitCode, 2);
        return true;
      }
    );
  });
});


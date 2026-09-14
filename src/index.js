import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parseCliArgs, getHelpText } from './cli/args.js';
import { checkTargetReadiness } from './core/probe.js';
import { loadOpenApiSpec } from './parser/openapi-loader.js';
import { extractEndpoints } from './parser/openapi-extractor.js';
import { loadAuthPolicy, parseAuthPolicy, AuthPolicy, PolicyValidationError, PolicySyntaxError } from './parser/policy-parser.js';
import { reconcile, ReconciliationError, RULE_SOURCES } from './parser/reconciler.js';
import { generateTestMatrix, calculateExpectedStatus, TEST_CATEGORIES, interpolatePath } from './matrix/planner.js';
import {
  mintMockJwt,
  synthesizePersonaJwt,
  verifyJwt,
  decodeJwt,
  base64UrlEncode,
  base64UrlDecode,
  generateKeyPair,
  detectKeyType,
  SUPPORTED_ALGORITHMS,
  JwtError,
  setNestedProperty,
} from './auth/jwt.js';

export {
  parseCliArgs,
  getHelpText,
  checkTargetReadiness,
  loadOpenApiSpec,
  extractEndpoints,
  loadAuthPolicy,
  parseAuthPolicy,
  AuthPolicy,
  PolicyValidationError,
  PolicySyntaxError,
  reconcile,
  ReconciliationError,
  RULE_SOURCES,
  generateTestMatrix,
  calculateExpectedStatus,
  TEST_CATEGORIES,
  interpolatePath,
  mintMockJwt,
  synthesizePersonaJwt,
  verifyJwt,
  decodeJwt,
  base64UrlEncode,
  base64UrlDecode,
  generateKeyPair,
  detectKeyType,
  SUPPORTED_ALGORITHMS,
  JwtError,
  setNestedProperty,
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function getPackageVersion() {
  try {
    const pkgPath = join(__dirname, '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    return pkg.version || '1.0.0';
  } catch {
    return '1.0.0';
  }
}

/**
 * Main CLI pipeline orchestrator.
 * 
 * @param {string[]} [rawArgs=process.argv.slice(2)] - Process CLI arguments
 * @param {Record<string, string>} [env=process.env] - Process environment variables
 * @returns {Promise<number>} Process exit code (0, 1, or 2)
 */
export async function runCli(rawArgs = process.argv.slice(2), env = process.env) {
  let config;
  try {
    const parsed = parseCliArgs(rawArgs, env);

    if (parsed.help) {
      process.stdout.write(getHelpText() + '\n');
      return 0;
    }

    if (parsed.version) {
      process.stdout.write(`authz-gatekeeper v${getPackageVersion()}\n`);
      return 0;
    }

    config = parsed;
  } catch (err) {
    process.stderr.write(`\n❌ Error: ${err.message}\n\n`);
    return err.exitCode || 2;
  }

  try {
    process.stdout.write(`\n🛡️  Authz CI Gatekeeper v${getPackageVersion()}\n`);
    process.stdout.write(`Target:      ${config.target}\n`);
    process.stdout.write(`Spec:        ${config.spec}\n`);
    if (config.policy) {
      process.stdout.write(`Policy:      ${config.policy}\n`);
    }
    process.stdout.write(`Output:      ${config.outDir}\n`);
    process.stdout.write(`Concurrency: ${config.concurrency}\n\n`);

    // Target Readiness Probe
    if (!config.noProbe) {
      process.stdout.write(`🔍 Probing target server readiness at ${config.target}${config.healthPath}...\n`);
      const probe = await checkTargetReadiness({
        targetUrl: config.target,
        healthPath: config.healthPath,
        timeoutMs: 30000,
        specUrl: config.spec,
      });
      process.stdout.write(`✅ Target service is responsive at ${probe.endpoint} (HTTP ${probe.status} in ${probe.durationMs}ms)\n\n`);
    } else {
      process.stdout.write(`⏩ Target readiness probe bypassed (--no-probe)\n\n`);
    }

    // Schema Ingestion & Normalization
    process.stdout.write(`📖 Ingesting OpenAPI specification from ${config.spec}...\n`);
    const openApiSpec = await loadOpenApiSpec(config.spec);
    const endpoints = extractEndpoints(openApiSpec);
    const pathCount = Object.keys(openApiSpec.paths || {}).length;
    process.stdout.write(`✅ Ingested "${openApiSpec.info.title}" (v${openApiSpec.info.version}): ${pathCount} paths (${endpoints.length} operations defined).\n\n`);

    // Policy Loading & Reconciliation (if policy specified)
    let reconciliation = null;
    if (config.policy) {
      process.stdout.write(`📋 Ingesting authorization policy from ${config.policy}...\n`);
      const authPolicy = await loadAuthPolicy(config.policy);
      process.stdout.write(`✅ Policy loaded: ${authPolicy.roles.length} roles defined (${authPolicy.roles.join(', ')}).\n\n`);

      process.stdout.write(`⚖️  Reconciling specification endpoints with authorization policy...\n`);
      reconciliation = reconcile(endpoints, authPolicy, {
        allowValidationErrors: config.allowValidationErrors,
      });
      process.stdout.write(
        `✅ Reconciled ${reconciliation.contracts.length} endpoints (${reconciliation.summary.protectedEndpoints} protected, ${reconciliation.summary.anonymousEndpoints} anonymous, ${reconciliation.summary.tenantBoundaryEndpoints} tenant-isolated).\n\n`
      );

      if (reconciliation.warnings.length > 0) {
        for (const w of reconciliation.warnings) {
          process.stdout.write(`⚠️  Warning: ${w}\n`);
        }
        process.stdout.write('\n');
      }
    }

    process.stdout.write(`✨ Workspace ingestion and policy reconciliation complete.\n`);
    return 0;
  } catch (err) {
    process.stderr.write(`\n❌ Gatekeeper Execution Failure:\n${err.message}\n\n`);
    return err.exitCode || 2;
  }
}


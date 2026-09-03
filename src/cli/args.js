import { parseArgs } from 'node:util';

export const CLI_OPTIONS = {
  spec: {
    type: 'string',
    short: 's',
  },
  policy: {
    type: 'string',
    short: 'p',
  },
  target: {
    type: 'string',
    short: 't',
  },
  'jwt-secret': {
    type: 'string',
  },
  out: {
    type: 'string',
    short: 'o',
  },
  'health-path': {
    type: 'string',
  },
  'no-probe': {
    type: 'boolean',
  },
  'allow-validation-errors': {
    type: 'boolean',
  },
  concurrency: {
    type: 'string',
    short: 'c',
  },
  timeout: {
    type: 'string',
  },
  help: {
    type: 'boolean',
    short: 'h',
    default: false,
  },
  version: {
    type: 'boolean',
    short: 'v',
    default: false,
  },
};

/**
 * Generates formatted CLI help documentation.
 */
export function getHelpText() {
  return `
Authz CI Gatekeeper (gatekeeper)
Automated fine-grained authorization & multi-tenant isolation testing for CI/CD.

Usage:
  gatekeeper [options]
  gatekeeper scan [options]

Required Options (or environment variables):
  -s, --spec <path|url>        Path or URL to OpenAPI specification (JSON/YAML)
                               [env: GATEKEEPER_SPEC_FILE]
  -t, --target <url>           Base URL of the target server (e.g. http://localhost:8000)
                               [env: GATEKEEPER_TARGET_URL]
  --jwt-secret <secret>        Shared HMAC secret for synthetic JWT generation
                               [env: GATEKEEPER_JWT_SECRET]

Additional Options:
  -p, --policy <path>          Path to auth-matrix.yaml policy manifest
                               [env: GATEKEEPER_POLICY_FILE]
  -o, --out <dir>              Output directory for CI test artifacts (default: ./gatekeeper-out)
                               [env: GATEKEEPER_OUT_DIR]
  --health-path <path>         Path for server readiness probe (default: /health)
  --no-probe                   Bypass readiness probe prior to test matrix execution
  --allow-validation-errors    Count 400/422 status as Auth Passed on authorized endpoints
  -c, --concurrency <number>   Max concurrent requests during dispatch (default: 10)
  --timeout <ms>               Request timeout in milliseconds (default: 5000)
  -h, --help                   Display this help message and exit
  -v, --version                Display Gatekeeper version and exit

Exit Codes:
  0  All authorization assertions passed
  1  Authorization violations or cross-tenant BOLA leaks detected
  2  Configuration, input, or target connectivity error
`;
}

/**
 * Parses raw CLI arguments and environment variables into a validated configuration object.
 * 
 * @param {string[]} rawArgs - Process arguments (e.g., process.argv.slice(2))
 * @param {Record<string, string>} [env=process.env] - Environment variables
 * @returns {object} Parsed and validated configuration, or { help: true } / { version: true }
 */
export function parseCliArgs(rawArgs = [], env = process.env) {
  // Strip optional 'scan' subcommand if passed
  const normalizedArgs = rawArgs.length > 0 && rawArgs[0] === 'scan' ? rawArgs.slice(1) : rawArgs;

  let parsed;
  try {
    parsed = parseArgs({
      args: normalizedArgs,
      options: CLI_OPTIONS,
      allowPositionals: false,
    });
  } catch (err) {
    const error = new Error(`Invalid CLI argument: ${err.message}`);
    error.code = 'ERR_INVALID_ARGS';
    error.exitCode = 2;
    throw error;
  }

  const { values } = parsed;

  if (values.help) {
    return { help: true };
  }

  if (values.version) {
    return { version: true };
  }

  // Resolve values prioritizing CLI flags over environment variables
  const spec = values.spec || env.GATEKEEPER_SPEC_FILE;
  const policy = values.policy || env.GATEKEEPER_POLICY_FILE || null;
  const target = values.target || env.GATEKEEPER_TARGET_URL;
  const jwtSecret = values['jwt-secret'] || env.GATEKEEPER_JWT_SECRET;
  const outDir = values.out || env.GATEKEEPER_OUT_DIR || './gatekeeper-out';
  const healthPath = values['health-path'] || env.GATEKEEPER_HEALTH_PATH || '/health';
  const noProbe = values['no-probe'] !== undefined 
    ? Boolean(values['no-probe']) 
    : (env.GATEKEEPER_NO_PROBE === 'true' || env.GATEKEEPER_NO_PROBE === '1');
  const allowValidationErrors = values['allow-validation-errors'] !== undefined 
    ? Boolean(values['allow-validation-errors']) 
    : (env.GATEKEEPER_ALLOW_VALIDATION_ERRORS === 'true' || env.GATEKEEPER_ALLOW_VALIDATION_ERRORS === '1');

  const concurrencyRaw = values.concurrency || env.GATEKEEPER_CONCURRENCY || '10';
  const concurrency = parseInt(concurrencyRaw, 10);
  if (isNaN(concurrency) || concurrency <= 0) {
    const error = new Error(`Invalid concurrency value: "${concurrencyRaw}". Must be a positive integer.`);
    error.code = 'ERR_INVALID_CONFIG';
    error.exitCode = 2;
    throw error;
  }

  const timeoutRaw = values.timeout || env.GATEKEEPER_TIMEOUT || '5000';
  const timeout = parseInt(timeoutRaw, 10);
  if (isNaN(timeout) || timeout <= 0) {
    const error = new Error(`Invalid timeout value: "${timeoutRaw}". Must be a positive integer.`);
    error.code = 'ERR_INVALID_CONFIG';
    error.exitCode = 2;
    throw error;
  }

  // Check required parameters
  const missing = [];
  if (!spec) missing.push('--spec (or GATEKEEPER_SPEC_FILE)');
  if (!target) missing.push('--target (or GATEKEEPER_TARGET_URL)');
  if (!jwtSecret) missing.push('--jwt-secret (or GATEKEEPER_JWT_SECRET)');

  if (missing.length > 0) {
    const error = new Error(`Missing required configuration options:\n  • ${missing.join('\n  • ')}\n\nRun 'gatekeeper --help' for usage guidance.`);
    error.code = 'ERR_MISSING_REQUIRED_CONFIG';
    error.exitCode = 2;
    throw error;
  }

  // Normalize target URL (strip trailing slash)
  const normalizedTarget = target.endsWith('/') ? target.slice(0, -1) : target;

  return {
    spec,
    policy,
    target: normalizedTarget,
    jwtSecret,
    outDir,
    healthPath: healthPath.startsWith('/') ? healthPath : `/${healthPath}`,
    noProbe,
    allowValidationErrors,
    concurrency,
    timeout,
  };
}

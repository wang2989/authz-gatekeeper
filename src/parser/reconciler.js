import { AuthPolicy, parseAuthPolicy, PolicyValidationError } from './policy-parser.js';

export const RULE_SOURCES = {
  OPENAPI_ANNOTATION: 'openapi-annotation',
  MATRIX_EXACT: 'matrix-exact',
  MATRIX_GLOB: 'matrix-glob',
  MATRIX_METHOD_DEFAULT: 'matrix-method-default',
  MATRIX_GLOBAL_DEFAULT: 'matrix-global-default',
  UNMAPPED_ALLOW: 'unmapped-allow',
  UNMAPPED_DENY: 'unmapped-deny',
};

/**
 * Custom error class for policy and specification reconciliation errors.
 */
export class ReconciliationError extends Error {
  constructor(message, code = 'ERR_RECONCILIATION') {
    super(message);
    this.name = 'ReconciliationError';
    this.code = code;
    this.exitCode = 2;
  }
}

/**
 * Detects multi-tenant isolation boundaries and binds mock entity fixtures.
 * 
 * @param {object} endpoint - Extracted endpoint definition
 * @param {AuthPolicy} authPolicy - Parsed authorization policy
 * @returns {{ hasTenantBoundary: boolean, tenantParameter: string|null, fixtures: { primary: Record<string, string>, secondary: Record<string, string> } }}
 */
export function detectTenantBoundary(endpoint, authPolicy) {
  const rawTenantClaim = authPolicy.jwt?.tenant_claim;
  const tenantClaim = typeof rawTenantClaim === 'string' && rawTenantClaim.trim().length > 0
    ? rawTenantClaim.trim()
    : 'tenant_id';
  const paramCandidates = new Set([
    'tenant_id',
    'tenantid',
    'tenant-id',
    'tid',
    'org_id',
    'orgid',
    'org-id',
    'account_id',
    'accountid',
    tenantClaim.toLowerCase(),
  ]);

  const pathParams = endpoint.pathParameters || [];
  let detectedParam = null;

  for (const p of pathParams) {
    if (paramCandidates.has(p.toLowerCase())) {
      detectedParam = p;
      break;
    }
  }

  // Fall back to checking parameter fixtures declared in auth policy
  if (!detectedParam && authPolicy.parameters) {
    for (const p of pathParams) {
      if (authPolicy.parameters[p]) {
        detectedParam = p;
        break;
      }
    }
  }

  const hasTenantBoundary = detectedParam !== null;

  const fixtures = {
    primary: {},
    secondary: {},
  };

  for (const param of pathParams) {
    if (authPolicy.parameters && authPolicy.parameters[param]) {
      const seeded = authPolicy.parameters[param];
      fixtures.primary[param] = seeded.primary || `primary-${param}`;
      fixtures.secondary[param] = seeded.secondary || `secondary-${param}`;
    } else if (param === detectedParam) {
      const tenantFixtures = authPolicy.tenants?.fixtures || {};
      fixtures.primary[param] = tenantFixtures.primary?.id || 'tenant-alpha';
      fixtures.secondary[param] = tenantFixtures.secondary?.id || 'tenant-beta';
    } else {
      fixtures.primary[param] = `mock-${param}-1`;
      fixtures.secondary[param] = `mock-${param}-2`;
    }
  }

  return {
    hasTenantBoundary,
    tenantParameter: detectedParam,
    fixtures,
  };
}

/**
 * Computes the authorized and unauthorized caller role sets given required roles.
 * 
 * @param {string[]} requiredRoles - Directly required roles for the endpoint
 * @param {AuthPolicy} authPolicy - Parsed authorization policy
 * @param {boolean} [isProtected=false] - Whether the endpoint is protected
 * @returns {{ authorizedRoles: string[], unauthorizedRoles: string[] }}
 */
export function resolveEffectiveRoleSets(requiredRoles, authPolicy, isProtected = false) {
  const allRoles = authPolicy?.roles || [];

  if (!Array.isArray(requiredRoles) || requiredRoles.length === 0) {
    return {
      authorizedRoles: [],
      unauthorizedRoles: isProtected ? [...allRoles] : [],
    };
  }

  const authorizedSet = new Set();
  for (const reqRole of requiredRoles) {
    const callers = authPolicy.getAuthorizedCallers(reqRole);
    for (const caller of callers) {
      authorizedSet.add(caller);
    }
  }

  const unauthorizedRoles = allRoles.filter((r) => !authorizedSet.has(r));

  return {
    authorizedRoles: Array.from(authorizedSet),
    unauthorizedRoles,
  };
}

/**
 * Reconciles extracted OpenAPI endpoint definitions with a declarative authorization policy.
 * Resolves effective security rules per endpoint using the 5-layer precedence model:
 *   Layer 1: Explicit OpenAPI Operation Annotations (x-required-role, security: [], x-allow-anonymous)
 *   Layer 2: Exact Route Match in auth-matrix.yaml routes:
 *   Layer 3: Glob Wildcard Match in auth-matrix.yaml routes:
 *   Layer 4: Method Default in defaults.method_defaults
 *   Layer 5: Baseline Default in defaults.default_role (or zero-trust deny fallback)
 * 
 * @param {Array<object>} endpoints - Array of EndpointDefinition objects from extractEndpoints()
 * @param {AuthPolicy|object|string} authPolicyOrRaw - Parsed AuthPolicy instance or raw YAML/object
 * @param {object} [options={}] - Reconciliation configuration options
 * @returns {ReconciliationReport}
 */
export function reconcile(endpoints, authPolicyOrRaw, options = {}) {
  if (!Array.isArray(endpoints)) {
    throw new ReconciliationError('First argument to reconcile() must be an array of EndpointDefinition objects.');
  }

  let authPolicy;
  if (authPolicyOrRaw instanceof AuthPolicy) {
    authPolicy = authPolicyOrRaw;
  } else if (authPolicyOrRaw && typeof authPolicyOrRaw === 'object') {
    authPolicy = parseAuthPolicy(authPolicyOrRaw);
  } else if (typeof authPolicyOrRaw === 'string') {
    authPolicy = parseAuthPolicy(authPolicyOrRaw);
  } else {
    throw new ReconciliationError('Second argument to reconcile() must be an AuthPolicy instance, object, or YAML string.');
  }

  const preferPolicyOverSpec = Boolean(options.preferPolicyOverSpec);
  const warnings = [];
  const contracts = [];
  const byRuleSource = {
    [RULE_SOURCES.OPENAPI_ANNOTATION]: 0,
    [RULE_SOURCES.MATRIX_EXACT]: 0,
    [RULE_SOURCES.MATRIX_GLOB]: 0,
    [RULE_SOURCES.MATRIX_METHOD_DEFAULT]: 0,
    [RULE_SOURCES.MATRIX_GLOBAL_DEFAULT]: 0,
    [RULE_SOURCES.UNMAPPED_ALLOW]: 0,
    [RULE_SOURCES.UNMAPPED_DENY]: 0,
  };

  for (const endpoint of endpoints) {
    const route = endpoint.path;
    const method = endpoint.method ? endpoint.method.toUpperCase() : 'GET';

    let isAnonymous = false;
    let requiredRoles = [];
    let ruleSource = null;

    // Check for matching route rule in authPolicy
    const matchingMatrixRule = authPolicy.findMatchingRouteRule(route, method);

    // Option: preferPolicyOverSpec allows matrix rules to override OpenAPI spec annotations
    if (preferPolicyOverSpec && matchingMatrixRule) {
      if (matchingMatrixRule.allow_anonymous === true) {
        isAnonymous = true;
        requiredRoles = [];
      } else {
        isAnonymous = false;
        requiredRoles = matchingMatrixRule.roles || [];
      }
      ruleSource = matchingMatrixRule.isGlob ? RULE_SOURCES.MATRIX_GLOB : RULE_SOURCES.MATRIX_EXACT;
    }

    // Layer 1: Explicit OpenAPI Operation Annotations
    if (!ruleSource) {
      const hasExplicitRoles = Array.isArray(endpoint.requiredRoles) && endpoint.requiredRoles.length > 0;
      const isExplicitAnon = Boolean(endpoint.isExplicitAnonymous);

      if (hasExplicitRoles) {
        isAnonymous = false;
        requiredRoles = [...endpoint.requiredRoles];
        ruleSource = RULE_SOURCES.OPENAPI_ANNOTATION;

        // Diagnostic: check if OpenAPI requires roles undeclared in policy
        for (const role of requiredRoles) {
          if (!authPolicy.hasRole(role)) {
            warnings.push(
              `Endpoint [${method} ${route}] requires role "${role}" which is not defined in the authorization policy.`
            );
          }
        }
      } else if (isExplicitAnon) {
        isAnonymous = true;
        requiredRoles = [];
        ruleSource = RULE_SOURCES.OPENAPI_ANNOTATION;
      }
    }

    // Layer 2 & 3: Match from auth-matrix.yaml routes
    if (!ruleSource && matchingMatrixRule) {
      if (matchingMatrixRule.allow_anonymous === true) {
        isAnonymous = true;
        requiredRoles = [];
      } else {
        isAnonymous = false;
        requiredRoles = matchingMatrixRule.roles || [];
      }
      ruleSource = matchingMatrixRule.isGlob ? RULE_SOURCES.MATRIX_GLOB : RULE_SOURCES.MATRIX_EXACT;
    }

    // Layer 4: Method Default in defaults.method_defaults
    if (!ruleSource) {
      const methodDefaultRole = authPolicy.defaults.method_defaults[method];
      if (methodDefaultRole) {
        isAnonymous = false;
        requiredRoles = [methodDefaultRole];
        ruleSource = RULE_SOURCES.MATRIX_METHOD_DEFAULT;
      }
    }

    // Layer 5: Baseline Default in defaults.default_role
    if (!ruleSource) {
      if (authPolicy.defaults.default_role) {
        isAnonymous = false;
        requiredRoles = [authPolicy.defaults.default_role];
        ruleSource = RULE_SOURCES.MATRIX_GLOBAL_DEFAULT;
      } else if (authPolicy.defaults.unauthenticated_access === 'allow') {
        isAnonymous = true;
        requiredRoles = [];
        ruleSource = RULE_SOURCES.UNMAPPED_ALLOW;
      } else {
        // Zero-trust baseline deny
        isAnonymous = false;
        requiredRoles = [];
        ruleSource = RULE_SOURCES.UNMAPPED_DENY;
        warnings.push(
          `Endpoint [${method} ${route}] is unannotated and unmapped; falling back to zero-trust deny.`
        );
      }
    }

    // Track rule source count
    byRuleSource[ruleSource] = (byRuleSource[ruleSource] || 0) + 1;

    // Resolve effective authorized & unauthorized personas
    let { authorizedRoles, unauthorizedRoles } = resolveEffectiveRoleSets(
      requiredRoles,
      authPolicy,
      !isAnonymous
    );

    if (ruleSource === RULE_SOURCES.UNMAPPED_DENY) {
      authorizedRoles = [];
      unauthorizedRoles = [...(authPolicy.roles || [])];
    }

    // Multi-tenant boundary and fixtures
    const { hasTenantBoundary, tenantParameter, fixtures } = detectTenantBoundary(endpoint, authPolicy);

    contracts.push({
      path: route,
      rawPath: endpoint.rawPath || route,
      method,
      operationId: endpoint.operationId || null,
      summary: endpoint.summary || null,
      description: endpoint.description || null,
      tags: endpoint.tags || [],
      isAnonymous,
      requiredRoles,
      authorizedRoles,
      unauthorizedRoles,
      ruleSource,
      securityRequirements: endpoint.securityRequirements || [],
      scopesPerRequirement: endpoint.scopesPerRequirement || [],
      parameters: endpoint.parameters || [],
      pathParameters: endpoint.pathParameters || [],
      hasRequestBody: Boolean(endpoint.hasRequestBody),
      requestBodySchema: endpoint.requestBodySchema || null,
      hasTenantBoundary,
      tenantParameter,
      fixtures,
    });
  }

  const protectedEndpoints = contracts.filter((c) => !c.isAnonymous).length;
  const anonymousEndpoints = contracts.filter((c) => c.isAnonymous).length;
  const tenantBoundaryEndpoints = contracts.filter((c) => c.hasTenantBoundary).length;

  return {
    contracts,
    warnings,
    summary: {
      totalEndpoints: contracts.length,
      protectedEndpoints,
      anonymousEndpoints,
      tenantBoundaryEndpoints,
      byRuleSource,
    },
    authPolicy,
  };
}


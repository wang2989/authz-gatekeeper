/**
 * Permutation Matrix Planner for Authz Gatekeeper.
 * 
 * Generates comprehensive test matrices covering:
 * - Intra-tenant positive authorization assertions (INTRA_TENANT_ALLOW)
 * - Intra-tenant negative authorization assertions (INTRA_TENANT_DENY)
 * - Cross-tenant BOLA / IDOR isolation attack vectors (CROSS_TENANT_ATTACK)
 * - Anonymous / unauthenticated baseline vectors (ANONYMOUS_BASELINE)
 * 
 * @module matrix/planner
 */

/**
 * Standard test categories evaluated by the Gatekeeper matrix engine.
 */
export const TEST_CATEGORIES = Object.freeze({
  INTRA_TENANT_ALLOW: 'intra-tenant-allow',
  INTRA_TENANT_DENY: 'intra-tenant-deny',
  CROSS_TENANT_ATTACK: 'cross-tenant-attack',
  ANONYMOUS_BASELINE: 'anonymous-baseline',
});

/**
 * Interpolates path parameters in a route pattern using provided fixture values.
 * Falls back to `mock-${paramName}` if a parameter is not supplied in fixtures.
 * Preserves query strings and trailing slashes.
 * 
 * @param {string} pathPattern - OpenAPI route pattern (e.g. `/api/v1/{tenant_id}/projects/{project_id}`)
 * @param {Record<string, string|number>} [paramFixtures={}] - Key-value map of fixture parameter values
 * @returns {string} Fully interpolated target path
 */
export function interpolatePath(pathPattern, paramFixtures = {}) {
  if (typeof pathPattern !== 'string') {
    return '';
  }

  return pathPattern.replace(/\{([^}]+)\}/g, (_match, rawParamName) => {
    const paramName = rawParamName.trim();
    if (
      paramFixtures &&
      Object.prototype.hasOwnProperty.call(paramFixtures, paramName) &&
      paramFixtures[paramName] !== undefined &&
      paramFixtures[paramName] !== null
    ) {
      return String(paramFixtures[paramName]);
    }
    return `mock-${paramName}`;
  });
}

/**
 * Calculates the standard expected HTTP status code for a given test permutation.
 * 
 * @param {object} contract - Reconciled endpoint authorization contract
 * @param {object|null} persona - Caller persona definition
 * @param {string} testCategory - Test category from TEST_CATEGORIES
 * @returns {number} Standard expected HTTP status code
 */
export function calculateExpectedStatus(contract, persona, testCategory) {
  const method = (contract?.method || 'GET').toUpperCase();

  switch (testCategory) {
    case TEST_CATEGORIES.INTRA_TENANT_ALLOW: {
      if (method === 'POST') return 201;
      if (method === 'DELETE') return 204;
      return 200;
    }
    case TEST_CATEGORIES.INTRA_TENANT_DENY:
      return 403;
    case TEST_CATEGORIES.CROSS_TENANT_ATTACK:
      return 403;
    case TEST_CATEGORIES.ANONYMOUS_BASELINE: {
      if (contract?.isAnonymous === true) {
        if (method === 'POST') return 201;
        if (method === 'DELETE') return 204;
        return 200;
      }
      return 401;
    }
    default:
      return 200;
  }
}

/**
 * Generates a comprehensive test vector matrix across reconciled contracts,
 * personas, and isolation boundaries.
 * 
 * @param {Array<object>|object} contractsOrReport - Array of contracts or ReconciliationReport object
 * @param {object} [tenantConfig={}] - Tenant configuration or fixtures
 * @param {object} [options={}] - Matrix generation options (skipAnonymous, skipCrossTenant, categories, roles, methods)
 * @returns {Array<object> & { vectors: Array<object>, summary: object }} Augmented vector array
 */
export function generateTestMatrix(contractsOrReport, tenantConfig = {}, options = {}) {
  let contracts;
  if (Array.isArray(contractsOrReport)) {
    contracts = contractsOrReport;
  } else if (contractsOrReport && Array.isArray(contractsOrReport.contracts)) {
    contracts = contractsOrReport.contracts;
  } else {
    throw new TypeError('contractsOrReport must be an array of contracts or an object containing a contracts array.');
  }

  let effectiveTenantConfig = tenantConfig || {};
  let effectiveOptions = options || {};

  const knownOptionKeys = ['skipAnonymous', 'skipCrossTenant', 'categories', 'roles', 'methods'];
  const hasOptionKeys = Object.keys(effectiveTenantConfig).some((k) => knownOptionKeys.includes(k));
  const hasTenantKeys = Object.keys(effectiveTenantConfig).some((k) =>
    ['fixtures', 'primaryTenantId', 'secondaryTenantId', 'tenants', 'model'].includes(k)
  );

  // If options was passed as second argument
  if (hasOptionKeys && !hasTenantKeys && Object.keys(effectiveOptions).length === 0) {
    effectiveOptions = effectiveTenantConfig;
    effectiveTenantConfig = {};
  }

  const primaryTenantId =
    effectiveTenantConfig?.fixtures?.primary?.id ||
    effectiveTenantConfig?.primaryTenantId ||
    effectiveTenantConfig?.tenants?.fixtures?.primary?.id ||
    contractsOrReport?.authPolicy?.tenants?.fixtures?.primary?.id ||
    'tenant-alpha';

  const secondaryTenantId =
    effectiveTenantConfig?.fixtures?.secondary?.id ||
    effectiveTenantConfig?.secondaryTenantId ||
    effectiveTenantConfig?.tenants?.fixtures?.secondary?.id ||
    contractsOrReport?.authPolicy?.tenants?.fixtures?.secondary?.id ||
    'tenant-beta';

  const skipAnonymous = Boolean(effectiveOptions.skipAnonymous ?? effectiveTenantConfig.skipAnonymous);
  const skipCrossTenant = Boolean(effectiveOptions.skipCrossTenant ?? effectiveTenantConfig.skipCrossTenant);

  const categoriesFilter = (effectiveOptions.categories || effectiveTenantConfig.categories)
    ? new Set(effectiveOptions.categories || effectiveTenantConfig.categories)
    : null;

  const rolesFilter = (effectiveOptions.roles || effectiveTenantConfig.roles)
    ? new Set(effectiveOptions.roles || effectiveTenantConfig.roles)
    : null;

  const methodsFilter = (effectiveOptions.methods || effectiveTenantConfig.methods)
    ? new Set((effectiveOptions.methods || effectiveTenantConfig.methods).map((m) => m.toUpperCase()))
    : null;

  const vectors = [];

  for (const contract of contracts) {
    const method = (contract.method || 'GET').toUpperCase();
    const route = contract.path;

    if (methodsFilter && !methodsFilter.has(method)) {
      continue;
    }

    const primaryFixtures = { ...(contract.fixtures?.primary || {}) };
    if (
      contract.tenantParameter &&
      (effectiveTenantConfig?.fixtures?.primary?.id || effectiveTenantConfig?.primaryTenantId)
    ) {
      primaryFixtures[contract.tenantParameter] = primaryTenantId;
    }
    const targetPath = interpolatePath(route, primaryFixtures);

    const contractSummary = {
      path: route,
      method,
      operationId: contract.operationId ?? null,
      isAnonymous: Boolean(contract.isAnonymous),
      requiredRoles: Array.isArray(contract.requiredRoles) ? [...contract.requiredRoles] : [],
      ruleSource: contract.ruleSource ?? null,
      hasTenantBoundary: Boolean(contract.hasTenantBoundary),
    };
    const parameters = contract.parameters || [];
    const hasRequestBody = Boolean(contract.hasRequestBody);
    const requestBodySchema = contract.requestBodySchema ?? null;

    // A. Intra-Tenant Positive Assertions (INTRA_TENANT_ALLOW)
    const shouldRunAllow = !categoriesFilter || categoriesFilter.has(TEST_CATEGORIES.INTRA_TENANT_ALLOW);
    if (shouldRunAllow) {
      const authorizedRoles = Array.isArray(contract.authorizedRoles) ? contract.authorizedRoles : [];
      for (const role of authorizedRoles) {
        if (rolesFilter && !rolesFilter.has(role)) {
          continue;
        }

        const persona = {
          role,
          tenantId: primaryTenantId,
          userId: `user-${primaryTenantId}-${role}`,
          isAnonymous: false,
        };

        const expectedStatus = calculateExpectedStatus(contract, persona, TEST_CATEGORIES.INTRA_TENANT_ALLOW);
        const expectedStatusCodes =
          method === 'POST'
            ? [200, 201, 202, 204]
            : method === 'DELETE'
            ? [200, 202, 204]
            : [200, 204];

        vectors.push({
          id: `${TEST_CATEGORIES.INTRA_TENANT_ALLOW}::${method} ${route}::${role}`,
          category: TEST_CATEGORIES.INTRA_TENANT_ALLOW,
          method,
          route,
          path: targetPath,
          persona,
          targetTenant: primaryTenantId,
          isCrossTenant: false,
          expectedStatus,
          expectedStatusCodes,
          description: `Allow authorized ${role} access to ${method} ${route} within tenant ${primaryTenantId}`,
          contract: contractSummary,
          parameters,
          hasRequestBody,
          requestBodySchema,
        });
      }
    }

    // B. Intra-Tenant Negative Assertions (INTRA_TENANT_DENY)
    const shouldRunDeny = !categoriesFilter || categoriesFilter.has(TEST_CATEGORIES.INTRA_TENANT_DENY);
    if (shouldRunDeny && !contract.isAnonymous) {
      const unauthorizedRoles = Array.isArray(contract.unauthorizedRoles) ? contract.unauthorizedRoles : [];
      for (const role of unauthorizedRoles) {
        if (rolesFilter && !rolesFilter.has(role)) {
          continue;
        }

        const persona = {
          role,
          tenantId: primaryTenantId,
          userId: `user-${primaryTenantId}-${role}`,
          isAnonymous: false,
        };

        vectors.push({
          id: `${TEST_CATEGORIES.INTRA_TENANT_DENY}::${method} ${route}::${role}`,
          category: TEST_CATEGORIES.INTRA_TENANT_DENY,
          method,
          route,
          path: targetPath,
          persona,
          targetTenant: primaryTenantId,
          isCrossTenant: false,
          expectedStatus: 403,
          expectedStatusCodes: [403],
          description: `Deny unauthorized ${role} access to ${method} ${route} within tenant ${primaryTenantId}`,
          contract: contractSummary,
          parameters,
          hasRequestBody,
          requestBodySchema,
        });
      }
    }

    // C. Cross-Tenant Attack Vectors (CROSS_TENANT_ATTACK)
    const shouldRunCrossTenant =
      !skipCrossTenant && (!categoriesFilter || categoriesFilter.has(TEST_CATEGORIES.CROSS_TENANT_ATTACK));
    if (shouldRunCrossTenant && contract.hasTenantBoundary === true && !contract.isAnonymous) {
      const authorizedRoles = Array.isArray(contract.authorizedRoles) ? contract.authorizedRoles : [];
      for (const role of authorizedRoles) {
        if (rolesFilter && !rolesFilter.has(role)) {
          continue;
        }

        const persona = {
          role,
          tenantId: secondaryTenantId,
          userId: `attacker-${secondaryTenantId}-${role}`,
          isAnonymous: false,
        };

        vectors.push({
          id: `${TEST_CATEGORIES.CROSS_TENANT_ATTACK}::${method} ${route}::${role}`,
          category: TEST_CATEGORIES.CROSS_TENANT_ATTACK,
          method,
          route,
          path: targetPath,
          persona,
          targetTenant: primaryTenantId,
          isCrossTenant: true,
          expectedStatus: 403,
          expectedStatusCodes: [403, 404],
          description: `Prevent cross-tenant access to ${method} ${route} by tenant ${secondaryTenantId} (${role}) against tenant ${primaryTenantId}`,
          contract: contractSummary,
          parameters,
          hasRequestBody,
          requestBodySchema,
        });
      }
    }

    // D. Unauthenticated Baselines (ANONYMOUS_BASELINE)
    const shouldRunAnonymous =
      !skipAnonymous && (!categoriesFilter || categoriesFilter.has(TEST_CATEGORIES.ANONYMOUS_BASELINE));
    const allowsAnonymousPersona = !rolesFilter || rolesFilter.has(null) || rolesFilter.has('anonymous');

    if (shouldRunAnonymous && allowsAnonymousPersona) {
      const persona = {
        role: null,
        tenantId: null,
        userId: null,
        isAnonymous: true,
      };

      const expectedStatus = contract.isAnonymous
        ? calculateExpectedStatus(contract, null, TEST_CATEGORIES.ANONYMOUS_BASELINE)
        : 401;

      const expectedStatusCodes = contract.isAnonymous
        ? [200, 201, 202, 204]
        : [401, 403];

      const description = contract.isAnonymous
        ? `Allow unauthenticated access to public endpoint ${method} ${route}`
        : `Reject unauthenticated access to protected endpoint ${method} ${route}`;

      vectors.push({
        id: `${TEST_CATEGORIES.ANONYMOUS_BASELINE}::${method} ${route}::anonymous`,
        category: TEST_CATEGORIES.ANONYMOUS_BASELINE,
        method,
        route,
        path: targetPath,
        persona,
        targetTenant: primaryTenantId,
        isCrossTenant: false,
        expectedStatus,
        expectedStatusCodes,
        description,
        contract: contractSummary,
        parameters,
        hasRequestBody,
        requestBodySchema,
      });
    }
  }

  const byCategory = {
    [TEST_CATEGORIES.INTRA_TENANT_ALLOW]: 0,
    [TEST_CATEGORIES.INTRA_TENANT_DENY]: 0,
    [TEST_CATEGORIES.CROSS_TENANT_ATTACK]: 0,
    [TEST_CATEGORIES.ANONYMOUS_BASELINE]: 0,
  };

  const byMethod = {};
  const coveredRoutes = new Set();

  for (const v of vectors) {
    if (byCategory[v.category] !== undefined) {
      byCategory[v.category]++;
    } else {
      byCategory[v.category] = 1;
    }
    byMethod[v.method] = (byMethod[v.method] || 0) + 1;
    coveredRoutes.add(v.route);
  }

  const summary = {
    totalVectors: vectors.length,
    byCategory,
    byMethod,
    routesCovered: coveredRoutes.size,
  };

  vectors.vectors = vectors;
  vectors.summary = summary;

  return vectors;
}


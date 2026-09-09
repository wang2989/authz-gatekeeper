/**
 * OpenAPI Route & Security Annotation Extractor
 * 
 * Traverses normalized OpenAPI 3.0+ (and Swagger 2.0) objects, extracting strongly-typed
 * endpoint operations, parameters, request body schemas, and attached security/role annotations.
 */

const VALID_HTTP_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'trace']);

/**
 * Normalizes an API route template.
 * - Converts Express-style `:param` to OpenAPI `{param}`
 * - Normalizes consecutive slashes (`//` -> `/`)
 * - Ensures a leading slash
 * 
 * @param {string} pathStr - Raw path string
 * @returns {string} Normalized path string
 */
export function normalizePath(pathStr) {
  if (typeof pathStr !== 'string') return '/';

  let normalized = pathStr.trim();

  // Convert Express-style :param to {param}
  normalized = normalized.replace(/:([a-zA-Z0-9_]+)/g, '{$1}');

  // Normalize consecutive slashes
  normalized = normalized.replace(/\/+/g, '/');

  // Ensure leading slash
  if (!normalized.startsWith('/')) {
    normalized = `/${normalized}`;
  }

  // Strip trailing slash unless it's just "/"
  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

/**
 * Extracts variable names from a `{param}` route template.
 * 
 * @param {string} pathStr - Route path (e.g., "/api/v1/{tenant_id}/items/{id}")
 * @returns {string[]} Array of parameter names (e.g., ["tenant_id", "id"])
 */
export function extractPathVariables(pathStr) {
  const matches = pathStr.match(/\{([^{}]+)\}/g);
  if (!matches) return [];
  return matches.map((m) => m.slice(1, -1).replace(/^\+/, '').trim());
}

/**
 * Normalizes and deduplicates an array of OpenAPI parameter objects.
 * When duplicate parameters sharing the same (name, in) exist, later parameters override earlier ones.
 * 
 * @param {Array<object>} parameters - List of raw parameter objects
 * @returns {Array<object>} Deduplicated and normalized parameter list
 */
export function normalizeParameters(parameters = []) {
  if (!Array.isArray(parameters)) return [];

  const paramMap = new Map();

  for (const param of parameters) {
    if (!param || typeof param !== 'object' || !param.name) continue;

    const name = String(param.name).trim();
    const location = String(param.in || 'query').toLowerCase();
    const key = `${location}:${name}`;

    paramMap.set(key, {
      name,
      in: location,
      required: location === 'path' ? true : Boolean(param.required),
      description: param.description || null,
      schema: param.schema || null,
      example: param.example !== undefined ? param.example : null,
    });
  }

  return Array.from(paramMap.values());
}

/**
 * Extracts required role annotations declared via common OpenAPI vendor extensions.
 * Inspects x-required-role, x-required-roles, x-roles, and x-role.
 * 
 * @param {object} operationObj - OpenAPI Operation Object
 * @returns {string[]} Array of required role names
 */
export function extractRoles(operationObj) {
  if (!operationObj || typeof operationObj !== 'object') return [];

  const roleRaw =
    operationObj['x-required-role'] ||
    operationObj['x-required-roles'] ||
    operationObj['x-roles'] ||
    operationObj['x-role'];

  if (!roleRaw) return [];

  if (Array.isArray(roleRaw)) {
    return Array.from(new Set(roleRaw.map((r) => String(r).trim()).filter(Boolean)));
  }

  if (typeof roleRaw === 'string') {
    const trimmed = roleRaw.trim();
    if (trimmed.length > 0) {
      // Support comma-separated role strings: "OrgAdmin, SuperAdmin"
      return Array.from(
        new Set(
          trimmed
            .split(',')
            .map((r) => r.trim())
            .filter(Boolean)
        )
      );
    }
  }

  return [];
}

/**
 * Evaluates security requirements and determines whether an operation is public/anonymous.
 * 
 * @param {object} operationObj - OpenAPI Operation Object
 * @param {Array<object>} [rootSecurity=[]] - Global security requirements from spec root
 * @returns {{ isAnonymous: boolean, securityRequirements: Array<object>, requiredScopes: string[] }}
 */
export function extractSecurity(operationObj, rootSecurity = []) {
  const globalSec = Array.isArray(rootSecurity) ? rootSecurity : [];
  const hasExplicitOpSecurity = operationObj && Array.isArray(operationObj.security);

  let securityRequirements = [];

  if (hasExplicitOpSecurity) {
    securityRequirements = operationObj.security;
  } else if (globalSec.length > 0) {
    securityRequirements = globalSec;
  } else {
    securityRequirements = [];
  }

  // An endpoint allows anonymous access if:
  // 1. Neither operation nor root defines security (securityRequirements is empty)
  // 2. Explicit operation security: [] (disables root security)
  // 3. Any Security Requirement Object is empty `{}` (OpenAPI standard for anonymous alternative)
  // 4. Explicit vendor override: `x-allow-anonymous: true`
  const allowsAnonymousRequirement = securityRequirements.some(
    (req) => req && typeof req === 'object' && !Array.isArray(req) && Object.keys(req).length === 0
  );

  let isAnonymous = securityRequirements.length === 0 || allowsAnonymousRequirement;

  // Explicit vendor override
  if (operationObj && Boolean(operationObj['x-allow-anonymous'])) {
    isAnonymous = true;
  }

  // Extract OAuth2 / OIDC scopes from active security requirements (skipping empty objects)
  const scopeSet = new Set();
  for (const secRequirement of securityRequirements) {
    if (secRequirement && typeof secRequirement === 'object' && !Array.isArray(secRequirement)) {
      for (const scopes of Object.values(secRequirement)) {
        if (Array.isArray(scopes)) {
          for (const s of scopes) {
            if (s && typeof s === 'string') scopeSet.add(s.trim());
          }
        }
      }
    }
  }

  return {
    isAnonymous,
    securityRequirements,
    requiredScopes: Array.from(scopeSet),
  };
}

/**
 * Extracts request payload schema from an Operation Object for mutation verbs.
 * 
 * @param {object} operationObj - OpenAPI Operation Object
 * @returns {object|null} Payload schema object or null if not defined
 */
export function extractRequestBodySchema(operationObj) {
  if (!operationObj || !operationObj.requestBody || typeof operationObj.requestBody !== 'object') {
    return null;
  }

  const content = operationObj.requestBody.content;
  if (!content || typeof content !== 'object') return null;

  // Prioritize application/json
  if (content['application/json'] && content['application/json'].schema) {
    return content['application/json'].schema;
  }

  // Fall back to first declared content type schema
  for (const mediaType of Object.values(content)) {
    if (mediaType && mediaType.schema) {
      return mediaType.schema;
    }
  }

  return null;
}

/**
 * Traverses an OpenAPI specification object and extracts an array of endpoint operation definitions.
 * 
 * @param {object} openApiObj - Parsed and validated OpenAPI 3.0+ or Swagger 2.0 object
 * @returns {Array<object>} Array of structured EndpointDefinition objects
 */
export function extractEndpoints(openApiObj) {
  if (!openApiObj || typeof openApiObj !== 'object' || !openApiObj.paths || typeof openApiObj.paths !== 'object') {
    return [];
  }

  const rootSecurity = Array.isArray(openApiObj.security) ? openApiObj.security : [];
  const endpoints = [];

  for (const [rawPath, pathItem] of Object.entries(openApiObj.paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;

    const normalizedPath = normalizePath(rawPath);
    const templatePathVars = extractPathVariables(normalizedPath);

    // Path-level parameters apply across all operations on this path
    const pathLevelParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];

    for (const [methodKey, operationObj] of Object.entries(pathItem)) {
      const method = methodKey.toLowerCase();
      if (!VALID_HTTP_METHODS.has(method)) continue;
      if (!operationObj || typeof operationObj !== 'object') continue;

      // Merge path-level parameters with operation-level parameters
      const operationParams = Array.isArray(operationObj.parameters) ? operationObj.parameters : [];
      const mergedParams = normalizeParameters([...pathLevelParams, ...operationParams]);

      // Identify declared and template path parameters
      const declaredPathParams = mergedParams.filter((p) => p.in === 'path').map((p) => p.name);
      const allPathParams = Array.from(new Set([...templatePathVars, ...declaredPathParams]));

      // Security & Anonymous Access
      const { isAnonymous, securityRequirements, requiredScopes } = extractSecurity(operationObj, rootSecurity);

      // Roles from vendor extensions
      const requiredRoles = extractRoles(operationObj);

      // Request Body
      const requestBodySchema = extractRequestBodySchema(operationObj);

      endpoints.push({
        path: normalizedPath,
        rawPath,
        method: method.toUpperCase(),
        operationId: operationObj.operationId || null,
        summary: operationObj.summary || null,
        description: operationObj.description || null,
        tags: Array.isArray(operationObj.tags) ? operationObj.tags : [],
        parameters: mergedParams,
        pathParameters: allPathParams,
        requiredRoles,
        requiredScopes,
        securityRequirements,
        isAnonymous,
        hasRequestBody: Boolean(operationObj.requestBody),
        requestBodySchema,
      });
    }
  }

  return endpoints;
}


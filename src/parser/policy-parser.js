import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import YAML from 'yaml';
import { normalizePath } from './openapi-extractor.js';

/**
 * Custom error class for authorization policy validation failures.
 */
export class PolicyValidationError extends Error {
  constructor(message, code = 'ERR_POLICY_VALIDATION') {
    super(message);
    this.name = 'PolicyValidationError';
    this.code = code;
    this.exitCode = 2;
  }
}

/**
 * Custom error class for authorization policy syntax and parsing errors.
 */
export class PolicySyntaxError extends PolicyValidationError {
  constructor(message) {
    super(message, 'ERR_POLICY_SYNTAX');
    this.name = 'PolicySyntaxError';
  }
}

/**
 * Compiles a path pattern (supporting `{param}`, `*`, and `**`) into a regular expression.
 * 
 * @param {string} pattern - Path pattern (e.g. "/api/v1/{tenant_id}/admin/*")
 * @returns {{ regex: RegExp, isGlob: boolean }} Compiled regex and glob indicator
 */
export function compilePathPattern(pattern) {
  const isGlob = pattern.includes('*');
  const hasMultiSegmentGlob = pattern.includes('**');
  const hasSingleSegmentGlob = isGlob && !hasMultiSegmentGlob;

  // Split into path segments to reliably convert globs and parameter templates
  const segments = pattern.split('/');
  let paramCount = 0;
  let literalSegmentCount = 0;
  let literalCharCount = 0;

  const regexSegments = segments.map((seg) => {
    if (seg === '**') {
      return '.*';
    }
    if (seg === '*') {
      return '[^/]+';
    }
    // Match OpenAPI template parameter e.g. {tenant_id}
    if (/^\{[^{}]+\}$/.test(seg)) {
      paramCount++;
      return '[^/]+';
    }

    if (seg.length > 0) {
      literalSegmentCount++;
      literalCharCount += seg.length;
    }

    // Escape regex characters
    let escaped = seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    // Replace inline wildcards if any (e.g. "prefix-*")
    escaped = escaped.replace(/\\\*/g, '[^/]*');
    return escaped;
  });

  const hasParams = paramCount > 0;
  const isLiteral = !isGlob && !hasParams;

  // Precedence tiers:
  // Tier 1: Literal path (no params, no wildcards e.g. /users/me)
  // Tier 2: Parameterized path (has params, no wildcards e.g. /users/{id})
  // Tier 3: Single-segment glob wildcard (*) e.g. /users/*
  // Tier 4: Multi-segment glob wildcard (**) e.g. /users/**
  let tier = 1;
  if (isLiteral) {
    tier = 1;
  } else if (!isGlob && hasParams) {
    tier = 2;
  } else if (hasSingleSegmentGlob) {
    tier = 3;
  } else {
    tier = 4;
  }

  const regexStr = `^${regexSegments.join('/')}$`;
  return {
    regex: new RegExp(regexStr),
    isGlob,
    hasParams,
    paramCount,
    isLiteral,
    hasMultiSegmentGlob,
    hasSingleSegmentGlob,
    literalSegmentCount,
    literalCharCount,
    tier,
  };
}

/**
 * Validates the role graph for cyclic inheritance and unknown parents using 3-color DFS.
 * 
 * @param {Map<string, string[]>} adjacencyList - Directed graph of role inheritance (Role -> InheritedRoles)
 * @throws {PolicyValidationError} If a cycle or unknown parent is detected
 */
export function validateRoleGraph(adjacencyList) {
  const UNVISITED = 0;
  const VISITING = 1;
  const VISITED = 2;

  const state = new Map();
  for (const role of adjacencyList.keys()) {
    state.set(role, UNVISITED);
  }

  const stack = [];

  function dfs(u) {
    state.set(u, VISITING);
    stack.push(u);

    const neighbors = adjacencyList.get(u) || [];
    for (const v of neighbors) {
      if (!adjacencyList.has(v)) {
        throw new PolicyValidationError(`Role "${u}" inherits from undefined role "${v}".`);
      }

      const neighborState = state.get(v);
      if (neighborState === VISITING) {
        const cycleStartIndex = stack.indexOf(v);
        const cyclePath = [...stack.slice(cycleStartIndex), v].join(' -> ');
        throw new PolicyValidationError(`Cyclic role inheritance detected: ${cyclePath}`);
      }

      if (neighborState === UNVISITED) {
        dfs(v);
      }
    }

    stack.pop();
    state.set(u, VISITED);
  }

  for (const role of adjacencyList.keys()) {
    if (state.get(role) === UNVISITED) {
      dfs(role);
    }
  }
}

/**
 * Computes transitive inheritance and authorized callers for all declared roles.
 * 
 * @param {Map<string, string[]>} adjacencyList - Role inheritance graph
 * @returns {{ transitiveRoles: Map<string, Set<string>>, authorizedCallers: Map<string, Set<string>> }}
 */
export function computeTransitiveRoles(adjacencyList) {
  const transitiveRoles = new Map();
  const authorizedCallers = new Map();

  for (const role of adjacencyList.keys()) {
    transitiveRoles.set(role, new Set([role]));
    authorizedCallers.set(role, new Set([role]));
  }

  // Find all roles inherited by each role using BFS
  for (const role of adjacencyList.keys()) {
    const inherited = transitiveRoles.get(role);
    const queue = [...(adjacencyList.get(role) || [])];

    while (queue.length > 0) {
      const current = queue.shift();
      if (!inherited.has(current)) {
        inherited.add(current);
        const nextParents = adjacencyList.get(current) || [];
        for (const p of nextParents) {
          if (!inherited.has(p)) {
            queue.push(p);
          }
        }
      }
    }
  }

  // Reverse mapping: for each required role, which caller roles can satisfy it?
  for (const [callerRole, inheritedSet] of transitiveRoles.entries()) {
    for (const inheritedRole of inheritedSet) {
      if (authorizedCallers.has(inheritedRole)) {
        authorizedCallers.get(inheritedRole).add(callerRole);
      }
    }
  }

  return { transitiveRoles, authorizedCallers };
}

/**
 * Encapsulates a parsed, validated authorization policy manifest.
 */
export class AuthPolicy {
  constructor({
    version,
    roles,
    roleDescriptions = {},
    adjacencyList,
    transitiveRoles,
    authorizedCallers,
    tenants = {},
    jwt = {},
    defaults = {},
    routes = [],
    parameters = {},
    rawPolicy = {},
  }) {
    this.version = version;
    this.roles = roles;
    this.roleDescriptions = roleDescriptions;
    this.adjacencyList = adjacencyList;
    this.transitiveRoles = transitiveRoles;
    this.authorizedCallers = authorizedCallers;
    this.tenants = {
      model: tenants.model || 'flat',
      fixtures: tenants.fixtures || {},
      ...tenants,
    };
    this.jwt = {
      algorithm: jwt.algorithm || 'HS256',
      role_claim: jwt.role_claim || 'role',
      tenant_claim: jwt.tenant_claim || 'tenant_id',
      user_id_claim: jwt.user_id_claim || 'sub',
      ...jwt,
    };
    this.defaults = {
      unauthenticated_access: defaults.unauthenticated_access || 'deny',
      default_role: defaults.default_role || null,
      method_defaults: defaults.method_defaults || {},
      ...defaults,
    };
    this.routes = routes;
    this.parameters = parameters;
    this.rawPolicy = rawPolicy;
  }

  /**
   * Checks whether a role is defined in the policy.
   * 
   * @param {string} roleName
   * @returns {boolean}
   */
  hasRole(roleName) {
    return this.roles.includes(roleName);
  }

  /**
   * Returns all roles that the given role inherits (including itself).
   * 
   * @param {string} roleName
   * @returns {string[]}
   */
  getTransitiveRoles(roleName) {
    const set = this.transitiveRoles.get(roleName);
    return set ? Array.from(set) : [];
  }

  /**
   * Returns all caller roles that are authorized when `requiredRole` is demanded.
   * 
   * @param {string} requiredRole
   * @returns {string[]}
   */
  getAuthorizedCallers(requiredRole) {
    const set = this.authorizedCallers.get(requiredRole);
    return set ? Array.from(set) : [];
  }

  /**
   * Evaluates whether a caller role satisfies any of the required roles.
   * 
   * @param {string} callerRole - Role assigned to the caller
   * @param {string[]} requiredRoles - One or more roles required by the route
   * @returns {boolean}
   */
  isRoleAuthorized(callerRole, requiredRoles = []) {
    if (!callerRole || !Array.isArray(requiredRoles) || requiredRoles.length === 0) {
      return false;
    }
    const callerInherited = this.transitiveRoles.get(callerRole);
    if (!callerInherited) return false;

    return requiredRoles.some((reqRole) => callerInherited.has(reqRole));
  }

  /**
   * Finds the most specific route rule matching the given path and method.
   * Ranks all matches so literal paths win over parameterized routes and
   * wildcard globs rather than returning the first regex match.
   * 
   * @param {string} path - Target path e.g. "/users/me" or "/api/v1/{tenant_id}/projects"
   * @param {string} [method] - HTTP method e.g. "GET"
   * @returns {object|null} Matching route rule object or null
   */
  findMatchingRouteRule(path, method = null) {
    const normalizedTarget = normalizePath(path);
    const upperMethod = method ? method.toUpperCase() : null;

    const matches = [];

    for (const rule of this.routes) {
      // Check method restriction if specified in rule
      if (rule.methods && upperMethod && !rule.methods.includes(upperMethod)) {
        continue;
      }

      // Check exact path match or regex match
      const isExactMatch = rule.path === normalizedTarget;
      const isRegexMatch = rule.regex.test(normalizedTarget);

      if (isExactMatch || isRegexMatch) {
        matches.push({
          rule,
          isExactMatch,
        });
      }
    }

    if (matches.length === 0) {
      return null;
    }

    // Rank matching rules:
    // 1. Tier: Literal (1) > Parameterized (2) > Single-segment glob (3) > Multi-segment glob (4)
    // 2. Exact string equality (e.g. template identical to spec route)
    // 3. Higher literal segment count (more specific literal path segments)
    // 4. Fewer parameter placeholders
    // 5. Higher literal character count
    // 6. Tiebreaker: declaration order in routes
    matches.sort((a, b) => {
      if (a.rule.tier !== b.rule.tier) {
        return a.rule.tier - b.rule.tier;
      }

      if (a.isExactMatch && !b.isExactMatch) return -1;
      if (!a.isExactMatch && b.isExactMatch) return 1;

      if (a.rule.literalSegmentCount !== b.rule.literalSegmentCount) {
        return b.rule.literalSegmentCount - a.rule.literalSegmentCount;
      }

      if (a.rule.paramCount !== b.rule.paramCount) {
        return a.rule.paramCount - b.rule.paramCount;
      }

      if (a.rule.literalCharCount !== b.rule.literalCharCount) {
        return b.rule.literalCharCount - a.rule.literalCharCount;
      }

      return a.rule.index - b.rule.index;
    });

    return matches[0].rule;
  }
}

/**
 * Parses raw YAML or object content into a validated AuthPolicy instance.
 * 
 * @param {string|object} content - Raw YAML string or parsed object
 * @returns {AuthPolicy}
 * @throws {PolicyValidationError|PolicySyntaxError}
 */
export function parseAuthPolicy(content) {
  if (content === null || content === undefined) {
    throw new PolicyValidationError('Authorization policy content cannot be empty.');
  }

  let doc;
  if (typeof content === 'string') {
    if (content.trim().length === 0) {
      throw new PolicyValidationError('Authorization policy content cannot be empty.');
    }
    try {
      doc = YAML.parse(content);
    } catch (err) {
      throw new PolicySyntaxError(`Failed to parse authorization policy YAML: ${err.message}`);
    }
  } else if (typeof content === 'object') {
    doc = content;
  } else {
    throw new PolicyValidationError('Authorization policy content must be a YAML string or object.');
  }

  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new PolicyValidationError('Authorization policy manifest must be a top-level object.');
  }

  // 1. Validate version (Required string)
  if (doc.version === undefined || doc.version === null) {
    throw new PolicyValidationError("Missing required property 'version' in authorization policy.");
  }
  if (typeof doc.version !== 'string' || doc.version.trim().length === 0) {
    throw new PolicyValidationError("Property 'version' must be a non-empty string.");
  }
  const version = doc.version.trim();

  // 2. Validate roles (Required array or map)
  if (!doc.roles) {
    throw new PolicyValidationError("Missing required property 'roles' in authorization policy.");
  }

  const adjacencyList = new Map();
  const roleDescriptions = {};
  let roles = [];

  if (Array.isArray(doc.roles)) {
    // Format B: Ordered hierarchy list e.g. [SuperAdmin, OrgAdmin, Member, Viewer]
    if (doc.roles.length === 0) {
      throw new PolicyValidationError("Property 'roles' array cannot be empty.");
    }

    const seenRoles = new Set();
    for (let i = 0; i < doc.roles.length; i++) {
      const roleItem = doc.roles[i];
      if (typeof roleItem !== 'string' || roleItem.trim().length === 0) {
        throw new PolicyValidationError(`Invalid role at index ${i}: role name must be a non-empty string.`);
      }
      const role = roleItem.trim();
      if (seenRoles.has(role)) {
        throw new PolicyValidationError(`Duplicate role "${role}" found in roles list.`);
      }
      seenRoles.add(role);
      roles.push(role);
    }

    // Higher roles implicitly inherit immediate lower role in ordered list
    for (let i = 0; i < roles.length; i++) {
      const role = roles[i];
      const nextRole = i + 1 < roles.length ? [roles[i + 1]] : [];
      adjacencyList.set(role, nextRole);
    }
  } else if (typeof doc.roles === 'object') {
    // Format A: Directed inheritance map
    const roleKeys = Object.keys(doc.roles);
    if (roleKeys.length === 0) {
      throw new PolicyValidationError("Property 'roles' map cannot be empty.");
    }

    const seenRoles = new Set();
    roles = [];

    for (const [roleName, roleDef] of Object.entries(doc.roles)) {
      if (typeof roleName !== 'string' || roleName.trim().length === 0) {
        throw new PolicyValidationError(
          "Invalid role in 'roles' map: role name must be a non-empty string."
        );
      }
      const role = roleName.trim();
      if (seenRoles.has(role)) {
        throw new PolicyValidationError(`Duplicate role "${role}" found in 'roles' map.`);
      }
      seenRoles.add(role);
      roles.push(role);

      let parents = [];

      if (roleDef && typeof roleDef === 'object' && !Array.isArray(roleDef)) {
        if (roleDef.description && typeof roleDef.description === 'string') {
          roleDescriptions[role] = roleDef.description.trim();
        }

        if (roleDef.inherits !== undefined && roleDef.inherits !== null) {
          if (Array.isArray(roleDef.inherits)) {
            const seenParents = new Set();
            parents = [];
            for (let pIdx = 0; pIdx < roleDef.inherits.length; pIdx++) {
              const p = roleDef.inherits[pIdx];
              if (typeof p !== 'string' || p.trim().length === 0) {
                throw new PolicyValidationError(
                  `Invalid parent role at index ${pIdx} for role "${role}": expected non-empty string.`
                );
              }
              const parentRole = p.trim();
              if (seenParents.has(parentRole)) {
                throw new PolicyValidationError(
                  `Duplicate parent role "${parentRole}" found in 'inherits' for role "${role}".`
                );
              }
              seenParents.add(parentRole);
              parents.push(parentRole);
            }
          } else if (typeof roleDef.inherits === 'string') {
            const trimmed = roleDef.inherits.trim();
            if (trimmed.length === 0) {
              throw new PolicyValidationError(
                `Property 'inherits' for role "${role}" cannot be an empty string.`
              );
            }
            parents = [trimmed];
          } else {
            throw new PolicyValidationError(`Role "${role}" property 'inherits' must be an array or string.`);
          }
        }
      } else if (roleDef !== null && roleDef !== undefined) {
        throw new PolicyValidationError(`Role definition for "${role}" must be an object or null.`);
      }

      adjacencyList.set(role, parents);
    }
  } else {
    throw new PolicyValidationError("Property 'roles' must be an array or object.");
  }

  // 3. Cycle and Undefined Parent Validation
  validateRoleGraph(adjacencyList);

  // 4. Compute Transitive Sets
  const { transitiveRoles, authorizedCallers } = computeTransitiveRoles(adjacencyList);

  // 5. Validate Defaults
  const defaults = doc.defaults || {};
  if (typeof defaults !== 'object' || Array.isArray(defaults)) {
    throw new PolicyValidationError("Property 'defaults' must be an object.");
  }

  if (defaults.unauthenticated_access !== undefined) {
    if (!['deny', 'allow'].includes(defaults.unauthenticated_access)) {
      throw new PolicyValidationError(
        `Invalid defaults.unauthenticated_access: "${defaults.unauthenticated_access}". Expected "deny" or "allow".`
      );
    }
  }

  if (defaults.default_role !== undefined && defaults.default_role !== null) {
    if (typeof defaults.default_role !== 'string' || defaults.default_role.trim().length === 0) {
      throw new PolicyValidationError(
        "Property 'defaults.default_role' must be a non-empty string."
      );
    }
    const defaultRole = defaults.default_role.trim();
    if (!roles.includes(defaultRole)) {
      throw new PolicyValidationError(
        `Default role "${defaults.default_role}" is not declared in 'roles'.`
      );
    }
  }

  const methodDefaults = {};
  if (defaults.method_defaults) {
    if (typeof defaults.method_defaults !== 'object' || Array.isArray(defaults.method_defaults)) {
      throw new PolicyValidationError("Property 'defaults.method_defaults' must be an object.");
    }
    const seenMethods = new Set();
    for (const [methodKey, roleVal] of Object.entries(defaults.method_defaults)) {
      if (typeof methodKey !== 'string' || methodKey.trim().length === 0) {
        throw new PolicyValidationError("Method default HTTP method cannot be empty or whitespace-only.");
      }
      const upperMethod = methodKey.trim().toUpperCase();
      if (seenMethods.has(upperMethod)) {
        throw new PolicyValidationError(`Duplicate method default for "${upperMethod}".`);
      }
      seenMethods.add(upperMethod);

      if (typeof roleVal !== 'string' || roleVal.trim().length === 0) {
        throw new PolicyValidationError(
          `Method default for ${upperMethod} must specify a non-empty string role.`
        );
      }
      const roleStr = roleVal.trim();
      if (!roles.includes(roleStr)) {
        throw new PolicyValidationError(
          `Method default for ${upperMethod} references undeclared role "${roleVal}".`
        );
      }
      methodDefaults[upperMethod] = roleStr;
    }
  }

  // 6. Validate and Compile Routes
  const normalizedRoutes = [];
  if (doc.routes !== undefined) {
    if (!Array.isArray(doc.routes)) {
      throw new PolicyValidationError("Property 'routes' must be an array.");
    }

    for (let i = 0; i < doc.routes.length; i++) {
      const rule = doc.routes[i];
      if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
        throw new PolicyValidationError(`Route rule at index ${i} must be an object.`);
      }

      if (!rule.path || typeof rule.path !== 'string') {
        throw new PolicyValidationError(`Route rule at index ${i} is missing required 'path' string.`);
      }

      const normalizedPath = normalizePath(rule.path);
      const patternMeta = compilePathPattern(normalizedPath);

      let methods = null;
      if (rule.methods !== undefined && rule.methods !== null) {
        if (Array.isArray(rule.methods)) {
          if (rule.methods.length === 0) {
            throw new PolicyValidationError(
              `Property 'methods' in route rule "${rule.path}" cannot be an empty array.`
            );
          }
          methods = rule.methods.map((m, idx) => {
            if (typeof m !== 'string' || m.trim().length === 0) {
              throw new PolicyValidationError(
                `Invalid HTTP method at index ${idx} in route rule "${rule.path}": expected non-empty string.`
              );
            }
            return m.trim().toUpperCase();
          });
        } else if (typeof rule.methods === 'string') {
          if (rule.methods.trim().length === 0) {
            throw new PolicyValidationError(
              `Property 'methods' in route rule "${rule.path}" cannot be an empty string.`
            );
          }
          methods = [rule.methods.trim().toUpperCase()];
        } else {
          throw new PolicyValidationError(
            `Property 'methods' in route rule "${rule.path}" must be a string or an array of strings, received ${typeof rule.methods}.`
          );
        }
      }

      let routeRoles = [];
      if (rule.roles !== undefined && rule.roles !== null) {
        if (Array.isArray(rule.roles)) {
          routeRoles = rule.roles.map((r, idx) => {
            if (typeof r !== 'string' || r.trim().length === 0) {
              throw new PolicyValidationError(
                `Invalid role at index ${idx} in route rule "${rule.path}": expected non-empty string.`
              );
            }
            return r.trim();
          });
        } else if (typeof rule.roles === 'string') {
          if (rule.roles.trim().length === 0) {
            throw new PolicyValidationError(
              `Property 'roles' in route rule "${rule.path}" cannot be an empty string.`
            );
          }
          routeRoles = [rule.roles.trim()];
        } else {
          throw new PolicyValidationError(
            `Property 'roles' in route rule "${rule.path}" must be a string or an array of strings, received ${typeof rule.roles}.`
          );
        }

        for (const r of routeRoles) {
          if (!roles.includes(r)) {
            throw new PolicyValidationError(
              `Route rule "${rule.path}" references undeclared role "${r}".`
            );
          }
        }
      }

      if (rule.allow_anonymous !== undefined && rule.allow_anonymous !== null) {
        if (typeof rule.allow_anonymous !== 'boolean') {
          throw new PolicyValidationError(
            `Property 'allow_anonymous' in route rule "${rule.path}" must be a boolean, received ${typeof rule.allow_anonymous}.`
          );
        }
      }

      normalizedRoutes.push({
        index: i,
        path: normalizedPath,
        rawPath: rule.path,
        methods,
        roles: routeRoles,
        allow_anonymous: rule.allow_anonymous === true,
        ...patternMeta,
      });
    }
  }

  // 7. Validate Tenants
  const tenants = doc.tenants && typeof doc.tenants === 'object' ? doc.tenants : {};

  // 8. Validate JWT
  const jwt = doc.jwt && typeof doc.jwt === 'object' ? doc.jwt : {};

  // 9. Validate Parameters
  const parameters = doc.parameters && typeof doc.parameters === 'object' ? doc.parameters : {};

  return new AuthPolicy({
    version,
    roles,
    roleDescriptions,
    adjacencyList,
    transitiveRoles,
    authorizedCallers,
    tenants,
    jwt,
    defaults: {
      ...defaults,
      method_defaults: methodDefaults,
    },
    routes: normalizedRoutes,
    parameters,
    rawPolicy: doc,
  });
}

/**
 * Reads and parses an authorization policy YAML file from the filesystem.
 * 
 * @param {string} filePath - Absolute or relative path to auth-matrix.yaml
 * @returns {Promise<AuthPolicy>}
 * @throws {PolicyValidationError} If the file does not exist or fails validation
 */
export async function loadAuthPolicy(filePath) {
  if (typeof filePath !== 'string' || filePath.trim().length === 0) {
    throw new PolicyValidationError('File path to authorization policy must be a non-empty string.');
  }

  const resolvedPath = resolve(process.cwd(), filePath.trim());
  let content;
  try {
    content = await readFile(resolvedPath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new PolicyValidationError(
        `Authorization policy file not found: ${resolvedPath}`,
        'ERR_POLICY_FILE_NOT_FOUND'
      );
    }
    throw new PolicyValidationError(
      `Failed to read authorization policy file: ${err.message}`,
      'ERR_POLICY_READ_FAILED'
    );
  }

  return parseAuthPolicy(content);
}


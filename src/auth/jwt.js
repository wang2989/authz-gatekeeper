import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';

/**
 * Supported cryptographic algorithms for JWT signing and verification.
 */
export const SUPPORTED_ALGORITHMS = Object.freeze({
  HS256: 'HS256',
  HS384: 'HS384',
  HS512: 'HS512',
  RS256: 'RS256',
  ES256: 'ES256',
});

/**
 * Custom error class for JWT operations.
 */
export class JwtError extends Error {
  /**
   * @param {string} message - Error description
   * @param {string} [code='ERR_JWT_ERROR'] - Machine-readable error code
   */
  constructor(message, code = 'ERR_JWT_ERROR') {
    super(message);
    this.name = 'JwtError';
    this.code = code;
  }
}

/**
 * Encodes input into unpadded base64url string according to RFC 7515.
 *
 * @param {string|Buffer|object} input - Data to encode (strings, buffers, or JSON objects)
 * @returns {string} Unpadded base64url string
 */
export function base64UrlEncode(input) {
  if (input === null || input === undefined) {
    throw new JwtError('Input to base64UrlEncode cannot be null or undefined', 'ERR_INVALID_INPUT');
  }

  let buf;
  if (Buffer.isBuffer(input)) {
    buf = input;
  } else if (typeof input === 'string') {
    buf = Buffer.from(input, 'utf8');
  } else if (typeof input === 'object') {
    buf = Buffer.from(JSON.stringify(input), 'utf8');
  } else {
    buf = Buffer.from(String(input), 'utf8');
  }

  return buf.toString('base64url');
}

/**
 * Decodes an unpadded base64url string into a UTF-8 string, Buffer, or parsed JSON object.
 *
 * @param {string} str - Unpadded base64url string
 * @param {boolean|'buffer'|{ asBuffer?: boolean, parseJson?: boolean }} [parseJson=false] - Decode mode
 * @returns {string|Buffer|object} Decoded content
 */
export function base64UrlDecode(str, parseJson = false) {
  if (typeof str !== 'string') {
    throw new JwtError('Input to base64UrlDecode must be a string', 'ERR_INVALID_INPUT');
  }

  if (!/^[A-Za-z0-9_-]*$/.test(str)) {
    throw new JwtError(
      'Invalid base64url encoding: input contains invalid characters or padding',
      'ERR_INVALID_TOKEN'
    );
  }

  const buf = Buffer.from(str, 'base64url');

  if (buf.toString('base64url') !== str) {
    throw new JwtError(
      'Invalid base64url encoding: input is not canonically encoded',
      'ERR_INVALID_TOKEN'
    );
  }

  if (parseJson === 'buffer' || (typeof parseJson === 'object' && parseJson !== null && parseJson.asBuffer === true)) {
    return buf;
  }

  const utf8 = buf.toString('utf8');

  const shouldParse = parseJson === true || (typeof parseJson === 'object' && parseJson !== null && parseJson.parseJson === true);
  if (shouldParse) {
    try {
      return JSON.parse(utf8);
    } catch (err) {
      throw new JwtError(`Failed to parse JSON payload: ${err.message}`, 'ERR_INVALID_TOKEN');
    }
  }

  return utf8;
}

/**
 * Sets a value at a target property path supporting dot-notation.
 * Includes prototype pollution guards against __proto__, constructor, and prototype keys.
 *
 * @param {Record<string, any>} target - Destination object
 * @param {string} path - Property path (e.g. 'realm_access.roles' or 'sub')
 * @param {any} value - Value to set
 * @returns {Record<string, any>} Mutated target object
 */
export function setNestedProperty(target, path, value) {
  if (!target || typeof target !== 'object' || Array.isArray(target)) {
    throw new TypeError('Target must be a non-null, non-array object');
  }

  if (typeof path !== 'string' || path.trim().length === 0) {
    return target;
  }

  const parts = path.trim().split('.');
  for (const part of parts) {
    if (part === '__proto__' || part === 'constructor' || part === 'prototype') {
      return target;
    }
  }

  let current = target;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (current[key] === undefined || current[key] === null || typeof current[key] !== 'object' || Array.isArray(current[key])) {
      current[key] = {};
    }
    current = current[key];
  }

  const lastKey = parts[parts.length - 1];
  current[lastKey] = value;

  return target;
}

/**
 * Generates in-memory PEM key pairs for asymmetric JWT signing and verification.
 *
 * @param {'RS256'|'ES256'} [algorithm='RS256'] - Target asymmetric algorithm
 * @returns {{ publicKey: string, privateKey: string }} Key pair PEM strings
 */
export function generateKeyPair(algorithm = 'RS256') {
  const normAlg = String(algorithm || 'RS256').toUpperCase();

  if (normAlg === 'RS256') {
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
  }

  if (normAlg === 'ES256') {
    return crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
  }

  throw new JwtError(
    `Unsupported key generation algorithm: ${algorithm}. Supported algorithms: RS256, ES256`,
    'ERR_UNSUPPORTED_ALGORITHM'
  );
}

/**
 * Detects the key type and asymmetric algorithm family from a secret, PEM string/Buffer, or KeyObject.
 *
 * @param {string|Buffer|crypto.KeyObject} secretOrKey - Cryptographic key or secret
 * @returns {{ type: string, asymmetricKeyType: string|null }} Key type metadata
 */
export function detectKeyType(secretOrKey) {
  if (
    secretOrKey instanceof crypto.KeyObject ||
    (typeof secretOrKey === 'object' && secretOrKey !== null && typeof secretOrKey.type === 'string' && 'asymmetricKeyType' in secretOrKey)
  ) {
    return {
      type: secretOrKey.type,
      asymmetricKeyType: secretOrKey.asymmetricKeyType || null,
    };
  }

  if (typeof secretOrKey === 'string' || Buffer.isBuffer(secretOrKey)) {
    const str = typeof secretOrKey === 'string' ? secretOrKey : secretOrKey.toString('utf8');
    if (/-----BEGIN [A-Z0-9_\- ]*(?:KEY|CERTIFICATE)-----/.test(str)) {
      try {
        if (str.includes('PRIVATE KEY')) {
          try {
            const privKey = crypto.createPrivateKey(secretOrKey);
            return {
              type: privKey.type,
              asymmetricKeyType: privKey.asymmetricKeyType || null,
            };
          } catch {
            const pubKey = crypto.createPublicKey(secretOrKey);
            return {
              type: pubKey.type,
              asymmetricKeyType: pubKey.asymmetricKeyType || null,
            };
          }
        } else {
          try {
            const pubKey = crypto.createPublicKey(secretOrKey);
            return {
              type: pubKey.type,
              asymmetricKeyType: pubKey.asymmetricKeyType || null,
            };
          } catch {
            const privKey = crypto.createPrivateKey(secretOrKey);
            return {
              type: privKey.type,
              asymmetricKeyType: privKey.asymmetricKeyType || null,
            };
          }
        }
      } catch (err) {
        throw new JwtError(`Failed to parse PEM key: ${err.message}`, 'ERR_INVALID_INPUT');
      }
    }
  }

  return { type: 'secret', asymmetricKeyType: null };
}

/**
 * Mints a signed mock JWT token string using Node.js native crypto.
 *
 * @param {Record<string, any>} claims - JWT payload claims
 * @param {string|Buffer} secretOrPrivateKey - HMAC secret or RSA/EC private key PEM
 * @param {string} [algorithm='HS256'] - Algorithm from SUPPORTED_ALGORITHMS
 * @param {object} [options={}] - Minting options (header, expiresInSeconds, issuer, audience, etc.)
 * @returns {string} Compact serialized JWT token (header.payload.signature)
 */
export function mintMockJwt(claims = {}, secretOrPrivateKey, algorithm = 'HS256', options = {}) {
  if (!secretOrPrivateKey) {
    throw new JwtError('Secret or private key is required to mint token', 'ERR_INVALID_INPUT');
  }

  const normAlg = String(algorithm || 'HS256').toUpperCase();
  if (!SUPPORTED_ALGORITHMS[normAlg]) {
    throw new JwtError(
      `Unsupported algorithm: ${algorithm}. Supported algorithms: ${Object.values(SUPPORTED_ALGORITHMS).join(', ')}`,
      'ERR_UNSUPPORTED_ALGORITHM'
    );
  }

  const keyInfo = detectKeyType(secretOrPrivateKey);

  if (normAlg === 'RS256') {
    if (keyInfo.asymmetricKeyType !== 'rsa') {
      throw new JwtError(
        `Algorithm RS256 requires an RSA private key, but received ${keyInfo.asymmetricKeyType || keyInfo.type} key`,
        'ERR_UNSUPPORTED_ALGORITHM'
      );
    }
    if (keyInfo.type === 'public') {
      throw new JwtError(
        'Algorithm RS256 requires an RSA private key, but received a public key',
        'ERR_INVALID_INPUT'
      );
    }
  } else if (normAlg === 'ES256') {
    if (keyInfo.asymmetricKeyType !== 'ec') {
      throw new JwtError(
        `Algorithm ES256 requires an EC private key, but received ${keyInfo.asymmetricKeyType || keyInfo.type} key`,
        'ERR_UNSUPPORTED_ALGORITHM'
      );
    }
    if (keyInfo.type === 'public') {
      throw new JwtError(
        'Algorithm ES256 requires an EC private key, but received a public key',
        'ERR_INVALID_INPUT'
      );
    }
  } else if (normAlg === 'HS256' || normAlg === 'HS384' || normAlg === 'HS512') {
    if (keyInfo.type !== 'secret' || keyInfo.asymmetricKeyType !== null) {
      throw new JwtError(
        `Algorithm ${normAlg} requires a symmetric secret key, but received ${keyInfo.asymmetricKeyType || keyInfo.type} key`,
        'ERR_UNSUPPORTED_ALGORITHM'
      );
    }
  }

  const customHeaders = options.header || options.headers || {};
  if (customHeaders.alg !== undefined && customHeaders.alg !== null) {
    if (String(customHeaders.alg).toUpperCase() !== normAlg) {
      throw new JwtError(
        `Conflicting algorithm in custom header: "${customHeaders.alg}" does not match signing algorithm "${normAlg}"`,
        'ERR_INVALID_INPUT'
      );
    }
  }

  const header = {
    typ: 'JWT',
    ...customHeaders,
    alg: normAlg,
  };

  const payload = { ...(claims || {}) };
  const now = Math.floor(Date.now() / 1000);

  if (payload.iat === undefined) {
    payload.iat = now;
  }

  if (payload.exp === undefined) {
    const ttl = options.expiresInSeconds ?? options.expiresIn ?? 3600;
    payload.exp = payload.iat + ttl;
  }

  if (payload.jti === undefined) {
    payload.jti = crypto.randomUUID();
  }

  const iss = options.issuer ?? options.iss;
  if (iss !== undefined && payload.iss === undefined) {
    payload.iss = iss;
  }

  const aud = options.audience ?? options.aud;
  if (aud !== undefined && payload.aud === undefined) {
    payload.aud = aud;
  }

  const headerB64 = base64UrlEncode(header);
  const payloadB64 = base64UrlEncode(payload);
  const signingInput = `${headerB64}.${payloadB64}`;

  let signatureB64;
  if (normAlg === 'HS256' || normAlg === 'HS384' || normAlg === 'HS512') {
    const hash = normAlg === 'HS256' ? 'sha256' : normAlg === 'HS384' ? 'sha384' : 'sha512';
    const sigBuf = crypto.createHmac(hash, secretOrPrivateKey).update(signingInput).digest();
    signatureB64 = sigBuf.toString('base64url');
  } else if (normAlg === 'RS256') {
    const sigBuf = crypto.sign('sha256', Buffer.from(signingInput), secretOrPrivateKey);
    signatureB64 = sigBuf.toString('base64url');
  } else if (normAlg === 'ES256') {
    const sigBuf = crypto.sign('sha256', Buffer.from(signingInput), {
      key: secretOrPrivateKey,
      dsaEncoding: 'ieee-p1363',
    });
    signatureB64 = sigBuf.toString('base64url');
  }

  return `${signingInput}.${signatureB64}`;
}

/**
 * Verifies a signed JWT token string against a secret or public key.
 *
 * @param {string} token - Serialized JWT token
 * @param {string|Buffer} secretOrPublicKey - HMAC secret or RSA/EC public key PEM
 * @param {object} [options={}] - Verification options (clockTolerance, issuer, audience, currentTime, etc.)
 * @returns {{ header: object, payload: object, valid: true }}
 */
export function verifyJwt(token, secretOrPublicKey, options = {}) {
  if (typeof token !== 'string' || token.trim().length === 0) {
    throw new JwtError('Token must be a non-empty string', 'ERR_INVALID_TOKEN');
  }

  if (!secretOrPublicKey) {
    throw new JwtError('Secret or public key is required for verification', 'ERR_INVALID_INPUT');
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    throw new JwtError(`Invalid JWT format: expected 3 parts, got ${parts.length}`, 'ERR_INVALID_TOKEN');
  }

  let header;
  try {
    header = base64UrlDecode(parts[0], true);
  } catch (err) {
    throw new JwtError(`Failed to decode JWT header: ${err.message}`, 'ERR_INVALID_TOKEN');
  }

  let payload;
  try {
    payload = base64UrlDecode(parts[1], true);
  } catch (err) {
    throw new JwtError(`Failed to decode JWT payload: ${err.message}`, 'ERR_INVALID_TOKEN');
  }

  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    throw new JwtError('JWT header must be a JSON object', 'ERR_INVALID_TOKEN');
  }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new JwtError('JWT payload must be a JSON object', 'ERR_INVALID_TOKEN');
  }

  const alg = header.alg;
  if (!alg || typeof alg !== 'string' || !SUPPORTED_ALGORITHMS[alg.toUpperCase()]) {
    throw new JwtError(`Unsupported or missing algorithm in header: ${alg}`, 'ERR_UNSUPPORTED_ALGORITHM');
  }

  const normAlg = alg.toUpperCase();
  const keyInfo = detectKeyType(secretOrPublicKey);

  // Automatically bind permitted algorithms to the key type by default to prevent algorithm confusion attacks
  if (keyInfo.asymmetricKeyType === 'rsa') {
    if (normAlg !== 'RS256') {
      throw new JwtError(
        `Algorithm "${normAlg}" is not permitted for RSA keys: algorithm confusion attack detected`,
        'ERR_UNSUPPORTED_ALGORITHM'
      );
    }
  } else if (keyInfo.asymmetricKeyType === 'ec') {
    if (normAlg !== 'ES256') {
      throw new JwtError(
        `Algorithm "${normAlg}" is not permitted for EC keys: algorithm confusion attack detected`,
        'ERR_UNSUPPORTED_ALGORITHM'
      );
    }
  } else if (keyInfo.type === 'secret') {
    if (!['HS256', 'HS384', 'HS512'].includes(normAlg)) {
      throw new JwtError(
        `Algorithm "${normAlg}" is not permitted for symmetric secrets: algorithm confusion attack detected`,
        'ERR_UNSUPPORTED_ALGORITHM'
      );
    }
  } else {
    throw new JwtError(
      `Unsupported key type "${keyInfo.type}" for JWT verification`,
      'ERR_UNSUPPORTED_ALGORITHM'
    );
  }

  // Caller-provided algorithm restrictions
  if (options.algorithm && typeof options.algorithm === 'string') {
    if (normAlg !== options.algorithm.toUpperCase()) {
      throw new JwtError(
        `Algorithm "${normAlg}" does not match required options.algorithm "${options.algorithm}"`,
        'ERR_UNSUPPORTED_ALGORITHM'
      );
    }
  }

  if (options.algorithms && (Array.isArray(options.algorithms) || options.algorithms instanceof Set)) {
    const allowed = Array.from(options.algorithms).map((a) => String(a).toUpperCase());
    if (!allowed.includes(normAlg)) {
      throw new JwtError(`Algorithm "${normAlg}" is not allowed by options.algorithms`, 'ERR_UNSUPPORTED_ALGORITHM');
    }
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  const signatureB64 = parts[2];

  let actualSig;
  try {
    actualSig = base64UrlDecode(signatureB64, 'buffer');
  } catch (err) {
    throw new JwtError(`Failed to decode JWT signature: ${err.message}`, 'ERR_INVALID_TOKEN');
  }

  let isSignatureValid = false;

  try {
    if (normAlg === 'HS256' || normAlg === 'HS384' || normAlg === 'HS512') {
      const hash = normAlg === 'HS256' ? 'sha256' : normAlg === 'HS384' ? 'sha384' : 'sha512';
      const expectedSig = crypto.createHmac(hash, secretOrPublicKey).update(signingInput).digest();
      if (expectedSig.length === actualSig.length && crypto.timingSafeEqual(expectedSig, actualSig)) {
        isSignatureValid = true;
      }
    } else if (normAlg === 'RS256') {
      isSignatureValid = crypto.verify('sha256', Buffer.from(signingInput), secretOrPublicKey, actualSig);
    } else if (normAlg === 'ES256') {
      isSignatureValid = crypto.verify(
        'sha256',
        Buffer.from(signingInput),
        {
          key: secretOrPublicKey,
          dsaEncoding: 'ieee-p1363',
        },
        actualSig
      );
    }
  } catch {
    throw new JwtError('Invalid token signature', 'ERR_INVALID_SIGNATURE');
  }

  if (!isSignatureValid) {
    throw new JwtError('Invalid token signature', 'ERR_INVALID_SIGNATURE');
  }

  const clockTolerance = options.clockTolerance ?? options.leeway ?? 0;
  const now = options.currentTime ?? options.now ?? Math.floor(Date.now() / 1000);
  if (!Number.isFinite(clockTolerance) || clockTolerance < 0 || !Number.isFinite(now)) {
    throw new JwtError('clockTolerance/leeway must be finite and non-negative; currentTime/now must be finite', 'ERR_INVALID_INPUT');
  }

  if (options.ignoreExpiration !== true && payload.exp !== undefined) {
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
      throw new JwtError('Invalid exp claim in payload', 'ERR_INVALID_TOKEN');
    }
    if (now >= payload.exp + clockTolerance) {
      throw new JwtError('Token expired', 'ERR_TOKEN_EXPIRED');
    }
  }

  if (options.ignoreNotBefore !== true && payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf)) {
      throw new JwtError('Invalid nbf claim in payload', 'ERR_INVALID_TOKEN');
    }
    if (now < payload.nbf - clockTolerance) {
      throw new JwtError('Token not yet valid', 'ERR_INVALID_TOKEN');
    }
  }

  const expectedIss = options.issuer ?? options.iss;
  if (expectedIss !== undefined) {
    if (Array.isArray(expectedIss)) {
      if (!expectedIss.includes(payload.iss)) {
        throw new JwtError(
          `Invalid token issuer: expected one of [${expectedIss.join(', ')}], got "${payload.iss}"`,
          'ERR_INVALID_TOKEN'
        );
      }
    } else if (payload.iss !== expectedIss) {
      throw new JwtError(
        `Invalid token issuer: expected "${expectedIss}", got "${payload.iss}"`,
        'ERR_INVALID_TOKEN'
      );
    }
  }

  const expectedAud = options.audience ?? options.aud;
  if (expectedAud !== undefined) {
    const payloadAuds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    const expectedAuds = Array.isArray(expectedAud) ? expectedAud : [expectedAud];
    const hasAudMatch = expectedAuds.some((ea) => payloadAuds.includes(ea));
    if (!hasAudMatch) {
      throw new JwtError(
        `Invalid token audience: expected "${expectedAud}", got "${payload.aud}"`,
        'ERR_INVALID_TOKEN'
      );
    }
  }

  return {
    header,
    payload,
    valid: true,
  };
}

/**
 * Decodes a JWT token string into its header, payload, and signature components
 * without performing signature verification.
 *
 * @param {string} token - Serialized JWT token
 * @returns {{ header: object, payload: object, signature: string }}
 */
export function decodeJwt(token) {
  if (typeof token !== 'string' || token.trim().length === 0) {
    throw new JwtError('Token must be a non-empty string', 'ERR_INVALID_TOKEN');
  }

  const parts = token.trim().split('.');
  if (parts.length !== 3) {
    throw new JwtError(`Invalid JWT format: expected 3 parts, got ${parts.length}`, 'ERR_INVALID_TOKEN');
  }

  let header;
  try {
    header = base64UrlDecode(parts[0], true);
  } catch (err) {
    throw new JwtError(`Failed to decode JWT header: ${err.message}`, 'ERR_INVALID_TOKEN');
  }

  let payload;
  try {
    payload = base64UrlDecode(parts[1], true);
  } catch (err) {
    throw new JwtError(`Failed to decode JWT payload: ${err.message}`, 'ERR_INVALID_TOKEN');
  }

  try {
    base64UrlDecode(parts[2], 'buffer');
  } catch (err) {
    throw new JwtError(`Failed to decode JWT signature: ${err.message}`, 'ERR_INVALID_TOKEN');
  }

  return {
    header,
    payload,
    signature: parts[2],
  };
}

/**
 * Checks if a claim name represents a plural list (e.g. roles, groups, permissions).
 *
 * @param {string} claimName - Claim property name
 * @returns {boolean}
 */
function isPluralClaim(claimName) {
  const leaf = claimName.split('.').pop().toLowerCase();
  return ['roles', 'groups', 'permissions'].includes(leaf) || (leaf.endsWith('s') && !['status'].includes(leaf));
}

/**
 * Synthesizes a signed mock JWT token for a specific matrix persona.
 *
 * @param {object|null} persona - Persona descriptor ({ role, tenantId, userId, isAnonymous })
 * @param {object} [jwtConfig={}] - JWT configuration from auth-matrix.yaml (or AuthPolicy instance)
 * @param {string|Buffer} secretOrPrivateKey - HMAC secret or RSA/EC private key PEM
 * @param {object} [options={}] - Additional claims, headers, overrides
 * @returns {string|null} Minted JWT string, or null if persona is anonymous / missing
 */
export function synthesizePersonaJwt(persona, jwtConfig = {}, secretOrPrivateKey, options = {}) {
  if (!persona || persona.isAnonymous === true) {
    return null;
  }

  const config = (jwtConfig && typeof jwtConfig === 'object' && jwtConfig.jwt) ? jwtConfig.jwt : (jwtConfig || {});

  const claims = { ...(options.claims || {}) };

  // 1. Role Claim
  const roleClaim = config.role_claim || config.roleClaim || options.role_claim || options.roleClaim || 'role';
  const shouldFormatAsArray = Boolean(options.asArray || isPluralClaim(roleClaim));
  const rawRole = persona.role ?? persona.roles;

  let roleValue;
  if (shouldFormatAsArray) {
    if (Array.isArray(rawRole)) {
      roleValue = [...rawRole];
    } else if (rawRole !== undefined && rawRole !== null) {
      roleValue = [rawRole];
    } else {
      roleValue = [];
    }
  } else {
    if (Array.isArray(rawRole)) {
      roleValue = rawRole[0] ?? null;
    } else {
      roleValue = rawRole ?? null;
    }
  }
  setNestedProperty(claims, roleClaim, roleValue);

  // 2. Tenant Claim
  const tenantClaim = config.tenant_claim || config.tenantClaim || options.tenant_claim || options.tenantClaim || 'tenant_id';
  const tenantId = persona.tenantId ?? persona.tenant_id;
  if (tenantId !== undefined && tenantId !== null) {
    setNestedProperty(claims, tenantClaim, tenantId);
  }

  // 3. User ID Claim
  const userIdClaim = config.user_id_claim || config.userIdClaim || options.user_id_claim || options.userIdClaim || 'sub';
  const userId = persona.userId ?? persona.user_id ?? persona.sub;
  if (userId !== undefined && userId !== null) {
    setNestedProperty(claims, userIdClaim, userId);
  }

  // Configuration options
  const issuer = config.issuer ?? options.issuer ?? options.iss;
  const audience = config.audience ?? options.audience ?? options.aud;
  const expiresInSeconds =
    config.expires_in ?? config.expiresIn ?? options.expiresInSeconds ?? options.expiresIn ?? options.expires_in ?? 3600;
  const algorithm = config.algorithm ?? options.algorithm ?? 'HS256';

  return mintMockJwt(claims, secretOrPrivateKey, algorithm, {
    ...options,
    issuer,
    audience,
    expiresInSeconds,
  });
}

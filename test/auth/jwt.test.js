import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  mintMockJwt,
  synthesizePersonaJwt,
  verifyJwt,
  decodeJwt,
  base64UrlEncode,
  base64UrlDecode,
  generateKeyPair,
  SUPPORTED_ALGORITHMS,
  JwtError,
  setNestedProperty,
} from '../../src/auth/jwt.js';
import * as IndexExports from '../../src/index.js';
import { AuthPolicy } from '../../src/parser/policy-parser.js';

describe('Native Mock JWT Synthesizer & Validator (src/auth/jwt.js)', () => {
  const DEFAULT_SECRET = 'super-secure-mock-test-secret-32-chars-long';

  describe('Package Exports & Index Re-exports', () => {
    it('re-exports all required JWT entities from src/index.js', () => {
      assert.strictEqual(IndexExports.mintMockJwt, mintMockJwt);
      assert.strictEqual(IndexExports.synthesizePersonaJwt, synthesizePersonaJwt);
      assert.strictEqual(IndexExports.verifyJwt, verifyJwt);
      assert.strictEqual(IndexExports.decodeJwt, decodeJwt);
      assert.strictEqual(IndexExports.base64UrlEncode, base64UrlEncode);
      assert.strictEqual(IndexExports.base64UrlDecode, base64UrlDecode);
      assert.strictEqual(IndexExports.generateKeyPair, generateKeyPair);
      assert.strictEqual(IndexExports.SUPPORTED_ALGORITHMS, SUPPORTED_ALGORITHMS);
      assert.strictEqual(IndexExports.JwtError, JwtError);
      assert.strictEqual(IndexExports.setNestedProperty, setNestedProperty);
    });

    it('freezes SUPPORTED_ALGORITHMS with required HMAC, RSA, and EC algorithms', () => {
      assert.ok(Object.isFrozen(SUPPORTED_ALGORITHMS));
      assert.strictEqual(SUPPORTED_ALGORITHMS.HS256, 'HS256');
      assert.strictEqual(SUPPORTED_ALGORITHMS.HS384, 'HS384');
      assert.strictEqual(SUPPORTED_ALGORITHMS.HS512, 'HS512');
      assert.strictEqual(SUPPORTED_ALGORITHMS.RS256, 'RS256');
      assert.strictEqual(SUPPORTED_ALGORITHMS.ES256, 'ES256');
    });

    it('initializes JwtError with name and code properties', () => {
      const err = new JwtError('Algorithm failure', 'ERR_UNSUPPORTED_ALGORITHM');
      assert.ok(err instanceof Error);
      assert.strictEqual(err.name, 'JwtError');
      assert.strictEqual(err.code, 'ERR_UNSUPPORTED_ALGORITHM');
      assert.strictEqual(err.message, 'Algorithm failure');
    });
  });

  describe('base64UrlEncode & base64UrlDecode', () => {
    it('encodes and decodes simple ASCII strings', () => {
      const input = 'Hello Authz Gatekeeper!';
      const encoded = base64UrlEncode(input);
      assert.ok(!encoded.includes('='));
      assert.ok(!encoded.includes('+'));
      assert.ok(!encoded.includes('/'));
      const decoded = base64UrlDecode(encoded);
      assert.strictEqual(decoded, input);
    });

    it('encodes and decodes raw binary Buffer', () => {
      const buf = Buffer.from([0x00, 0xff, 0x12, 0x34, 0x56, 0x78, 0x9a]);
      const encoded = base64UrlEncode(buf);
      const decodedBuf = base64UrlDecode(encoded, 'buffer');
      assert.ok(Buffer.isBuffer(decodedBuf));
      assert.deepStrictEqual(decodedBuf, buf);
    });

    it('encodes and decodes complex Unicode strings (emojis, CJK characters)', () => {
      const unicodeStr = '🛡️ 安全 gatekeeper 🚀 한국어 Русские символы';
      const encoded = base64UrlEncode(unicodeStr);
      assert.strictEqual(base64UrlDecode(encoded), unicodeStr);
    });

    it('encodes JSON objects directly and decodes with parseJson: true', () => {
      const obj = { sub: 'user-123', roles: ['Admin', 'Auditor'], active: true, count: 42 };
      const encoded = base64UrlEncode(obj);
      const decoded = base64UrlDecode(encoded, true);
      assert.deepStrictEqual(decoded, obj);
    });

    it('throws ERR_INVALID_INPUT if input to base64UrlEncode is null or undefined', () => {
      assert.throws(() => base64UrlEncode(null), {
        code: 'ERR_INVALID_INPUT',
      });
      assert.throws(() => base64UrlEncode(undefined), {
        code: 'ERR_INVALID_INPUT',
      });
    });

    it('throws ERR_INVALID_INPUT if input to base64UrlDecode is not a string', () => {
      assert.throws(() => base64UrlDecode(123), {
        code: 'ERR_INVALID_INPUT',
      });
    });

    it('throws ERR_INVALID_TOKEN when parseJson: true fails on non-JSON content', () => {
      const notJsonEncoded = base64UrlEncode('not-a-valid-json-string');
      assert.throws(() => base64UrlDecode(notJsonEncoded, true), {
        code: 'ERR_INVALID_TOKEN',
      });
    });
  });

  describe('setNestedProperty', () => {
    it('sets top-level property path', () => {
      const target = {};
      setNestedProperty(target, 'role', 'OrgAdmin');
      assert.strictEqual(target.role, 'OrgAdmin');
    });

    it('sets nested dot-notation property path (e.g. realm_access.roles)', () => {
      const target = {};
      setNestedProperty(target, 'realm_access.roles', ['SuperAdmin']);
      assert.deepStrictEqual(target.realm_access, { roles: ['SuperAdmin'] });
    });

    it('sets deeply nested paths and preserves existing sibling properties', () => {
      const target = {
        meta: { existingKey: 'preserved' },
      };
      setNestedProperty(target, 'meta.custom.nested.id', 999);
      assert.strictEqual(target.meta.existingKey, 'preserved');
      assert.strictEqual(target.meta.custom.nested.id, 999);
    });

    it('guards against prototype pollution (__proto__, constructor, prototype)', () => {
      const target = {};
      setNestedProperty(target, '__proto__.polluted', 'yes');
      setNestedProperty(target, 'constructor.prototype.polluted', 'yes');
      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(target.polluted, undefined);
    });

    it('throws TypeError if target is not a non-null object', () => {
      assert.throws(() => setNestedProperty(null, 'a.b', 1), TypeError);
      assert.throws(() => setNestedProperty('string', 'a.b', 1), TypeError);
      assert.throws(() => setNestedProperty([1, 2], 'a.b', 1), TypeError);
    });
  });

  describe('mintMockJwt & verifyJwt - Symmetric HMAC (HS256, HS384, HS512)', () => {
    it('mints and verifies an HS256 token with standard claims', () => {
      const claims = { sub: 'user-alpha-001', role: 'Member', tenant_id: 'tenant-alpha' };
      const token = mintMockJwt(claims, DEFAULT_SECRET, 'HS256');

      const parts = token.split('.');
      assert.strictEqual(parts.length, 3);

      const verification = verifyJwt(token, DEFAULT_SECRET);
      assert.strictEqual(verification.valid, true);
      assert.strictEqual(verification.header.alg, 'HS256');
      assert.strictEqual(verification.header.typ, 'JWT');
      assert.strictEqual(verification.payload.sub, 'user-alpha-001');
      assert.strictEqual(verification.payload.role, 'Member');
      assert.strictEqual(verification.payload.tenant_id, 'tenant-alpha');
      assert.ok(typeof verification.payload.iat === 'number');
      assert.ok(typeof verification.payload.exp === 'number');
      assert.ok(typeof verification.payload.jti === 'string');
      assert.strictEqual(verification.payload.exp - verification.payload.iat, 3600);
    });

    it('mints and verifies an HS384 token with Buffer secret and custom expiresIn', () => {
      const secretBuf = Buffer.from(DEFAULT_SECRET);
      const token = mintMockJwt({ sub: 'user-384' }, secretBuf, 'HS384', {
        expiresInSeconds: 7200,
        header: { kid: 'key-hs384-v1' },
      });

      const verification = verifyJwt(token, secretBuf);
      assert.strictEqual(verification.valid, true);
      assert.strictEqual(verification.header.alg, 'HS384');
      assert.strictEqual(verification.header.kid, 'key-hs384-v1');
      assert.strictEqual(verification.payload.exp - verification.payload.iat, 7200);
    });

    it('mints and verifies an HS512 token', () => {
      const token = mintMockJwt({ sub: 'user-512' }, DEFAULT_SECRET, 'HS512');
      const verification = verifyJwt(token, DEFAULT_SECRET);
      assert.strictEqual(verification.valid, true);
      assert.strictEqual(verification.header.alg, 'HS512');
      assert.strictEqual(verification.payload.sub, 'user-512');
    });

    it('throws ERR_INVALID_SIGNATURE if verified with incorrect secret', () => {
      const token = mintMockJwt({ sub: 'user-alpha' }, DEFAULT_SECRET, 'HS256');
      assert.throws(
        () => verifyJwt(token, 'different-wrong-secret-key-00000000'),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_SIGNATURE'
      );
    });
  });

  describe('mintMockJwt & verifyJwt - Asymmetric RSA (RS256)', () => {
    it('generates RSA 2048-bit keypair and verifies valid signature', () => {
      const keyPair = generateKeyPair('RS256');
      assert.ok(keyPair.publicKey.includes('BEGIN PUBLIC KEY'));
      assert.ok(keyPair.privateKey.includes('BEGIN PRIVATE KEY'));

      const token = mintMockJwt(
        { sub: 'rsa-user', role: 'SuperAdmin' },
        keyPair.privateKey,
        'RS256'
      );

      const verification = verifyJwt(token, keyPair.publicKey);
      assert.strictEqual(verification.valid, true);
      assert.strictEqual(verification.header.alg, 'RS256');
      assert.strictEqual(verification.payload.sub, 'rsa-user');
      assert.strictEqual(verification.payload.role, 'SuperAdmin');
    });

    it('rejects RS256 token signed by an unrelated RSA key', () => {
      const keyPairA = generateKeyPair('RS256');
      const keyPairB = generateKeyPair('RS256');

      const token = mintMockJwt({ sub: 'attacker' }, keyPairA.privateKey, 'RS256');

      assert.throws(
        () => verifyJwt(token, keyPairB.publicKey),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_SIGNATURE'
      );
    });
  });

  describe('mintMockJwt & verifyJwt - Asymmetric ECDSA (ES256)', () => {
    it('generates EC prime256v1 keypair and signs in IEEE P1363 format', () => {
      const keyPair = generateKeyPair('ES256');
      assert.ok(keyPair.publicKey.includes('BEGIN PUBLIC KEY'));
      assert.ok(keyPair.privateKey.includes('BEGIN PRIVATE KEY'));

      const token = mintMockJwt(
        { sub: 'ec-user', tenant_id: 'tenant-omega' },
        keyPair.privateKey,
        'ES256'
      );

      // Verify signature is 64 raw bytes (IEEE P1363 for P-256)
      const sigB64 = token.split('.')[2];
      const sigBuf = Buffer.from(sigB64, 'base64url');
      assert.strictEqual(sigBuf.length, 64);

      const verification = verifyJwt(token, keyPair.publicKey);
      assert.strictEqual(verification.valid, true);
      assert.strictEqual(verification.header.alg, 'ES256');
      assert.strictEqual(verification.payload.sub, 'ec-user');
      assert.strictEqual(verification.payload.tenant_id, 'tenant-omega');
    });

    it('rejects ES256 token signed by an unrelated EC key', () => {
      const keyPairA = generateKeyPair('ES256');
      const keyPairB = generateKeyPair('ES256');

      const token = mintMockJwt({ sub: 'ec-user' }, keyPairA.privateKey, 'ES256');

      assert.throws(
        () => verifyJwt(token, keyPairB.publicKey),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_SIGNATURE'
      );
    });

    it('throws ERR_UNSUPPORTED_ALGORITHM when generateKeyPair is called with invalid algorithm', () => {
      assert.throws(
        () => generateKeyPair('ED25519'),
        (err) => err instanceof JwtError && err.code === 'ERR_UNSUPPORTED_ALGORITHM'
      );
    });
  });

  describe('Tampering Rejection & Integrity Checks', () => {
    it('detects and rejects tampered payload (privilege escalation attack)', () => {
      const legitimateToken = mintMockJwt(
        { sub: 'user-1', role: 'Viewer', tenant_id: 'tenant-alpha' },
        DEFAULT_SECRET,
        'HS256'
      );

      const parts = legitimateToken.split('.');
      const payload = base64UrlDecode(parts[1], true);
      // Attacker elevates role from Viewer to SuperAdmin
      payload.role = 'SuperAdmin';
      const tamperedPayloadB64 = base64UrlEncode(payload);

      const tamperedToken = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;

      assert.throws(
        () => verifyJwt(tamperedToken, DEFAULT_SECRET),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_SIGNATURE'
      );
    });

    it('detects and rejects tampered header (algorithm switching attack)', () => {
      const legitimateToken = mintMockJwt({ sub: 'user-1' }, DEFAULT_SECRET, 'HS256');
      const parts = legitimateToken.split('.');
      const header = base64UrlDecode(parts[0], true);
      header.alg = 'HS384';
      const tamperedHeaderB64 = base64UrlEncode(header);

      const tamperedToken = `${tamperedHeaderB64}.${parts[1]}.${parts[2]}`;

      assert.throws(
        () => verifyJwt(tamperedToken, DEFAULT_SECRET),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_SIGNATURE'
      );
    });

    it('rejects corrupted / truncated signature bytes', () => {
      const token = mintMockJwt({ sub: 'user-1' }, DEFAULT_SECRET, 'HS256');
      const parts = token.split('.');
      const corruptedSig = parts[2].slice(0, -4) + 'AAAA';
      const corruptedToken = `${parts[0]}.${parts[1]}.${corruptedSig}`;

      assert.throws(
        () => verifyJwt(corruptedToken, DEFAULT_SECRET),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_SIGNATURE'
      );
    });
  });

  describe('Expiration & Clock Tolerance / Leeway', () => {
    it('rejects expired token with ERR_TOKEN_EXPIRED', () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredToken = mintMockJwt(
        { sub: 'expired-user', iat: now - 3600, exp: now - 100 },
        DEFAULT_SECRET,
        'HS256'
      );

      assert.throws(
        () => verifyJwt(expiredToken, DEFAULT_SECRET),
        (err) => err instanceof JwtError && err.code === 'ERR_TOKEN_EXPIRED'
      );
    });

    it('accepts expired token if within clockTolerance / leeway window', () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredToken = mintMockJwt(
        { sub: 'borderline-user', iat: now - 3600, exp: now - 10 },
        DEFAULT_SECRET,
        'HS256'
      );

      const verified = verifyJwt(expiredToken, DEFAULT_SECRET, {
        clockTolerance: 15,
      });
      assert.strictEqual(verified.valid, true);
    });

    it('rejects expired token when outside clockTolerance / leeway window', () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredToken = mintMockJwt(
        { sub: 'borderline-user', iat: now - 3600, exp: now - 20 },
        DEFAULT_SECRET,
        'HS256'
      );

      assert.throws(
        () => verifyJwt(expiredToken, DEFAULT_SECRET, { clockTolerance: 10 }),
        (err) => err instanceof JwtError && err.code === 'ERR_TOKEN_EXPIRED'
      );
    });

    it('allows expired token when ignoreExpiration: true is specified', () => {
      const now = Math.floor(Date.now() / 1000);
      const expiredToken = mintMockJwt(
        { sub: 'ignored-user', exp: now - 5000 },
        DEFAULT_SECRET,
        'HS256'
      );

      const verified = verifyJwt(expiredToken, DEFAULT_SECRET, {
        ignoreExpiration: true,
      });
      assert.strictEqual(verified.valid, true);
    });

    it('rejects token with future not-before (nbf) claim', () => {
      const now = Math.floor(Date.now() / 1000);
      const futureToken = mintMockJwt(
        { sub: 'future-user', nbf: now + 300 },
        DEFAULT_SECRET,
        'HS256'
      );

      assert.throws(
        () => verifyJwt(futureToken, DEFAULT_SECRET),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_TOKEN'
      );
    });
  });

  describe('Issuer (iss) & Audience (aud) Verification', () => {
    it('verifies matching issuer and audience successfully', () => {
      const token = mintMockJwt({ sub: 'user-aud' }, DEFAULT_SECRET, 'HS256', {
        issuer: 'authz-gatekeeper-auth',
        audience: 'https://api.example.com',
      });

      const verified = verifyJwt(token, DEFAULT_SECRET, {
        issuer: 'authz-gatekeeper-auth',
        audience: 'https://api.example.com',
      });
      assert.strictEqual(verified.valid, true);
      assert.strictEqual(verified.payload.iss, 'authz-gatekeeper-auth');
      assert.strictEqual(verified.payload.aud, 'https://api.example.com');
    });

    it('throws ERR_INVALID_TOKEN on issuer mismatch', () => {
      const token = mintMockJwt({ sub: 'user-aud' }, DEFAULT_SECRET, 'HS256', {
        issuer: 'authz-gatekeeper-auth',
      });

      assert.throws(
        () => verifyJwt(token, DEFAULT_SECRET, { issuer: 'unexpected-auth-issuer' }),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_TOKEN'
      );
    });

    it('supports issuer validation against an array of allowed issuers', () => {
      const token = mintMockJwt({ sub: 'user-iss' }, DEFAULT_SECRET, 'HS256', {
        issuer: 'issuer-beta',
      });

      const verified = verifyJwt(token, DEFAULT_SECRET, {
        issuer: ['issuer-alpha', 'issuer-beta'],
      });
      assert.strictEqual(verified.valid, true);

      assert.throws(
        () => verifyJwt(token, DEFAULT_SECRET, { issuer: ['issuer-charlie', 'issuer-delta'] }),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_TOKEN'
      );
    });

    it('verifies audience when token aud is an array of audiences', () => {
      const token = mintMockJwt(
        { sub: 'user-aud', aud: ['api://billing', 'api://users'] },
        DEFAULT_SECRET,
        'HS256'
      );

      const verified = verifyJwt(token, DEFAULT_SECRET, {
        audience: 'api://users',
      });
      assert.strictEqual(verified.valid, true);

      assert.throws(
        () => verifyJwt(token, DEFAULT_SECRET, { audience: 'api://unknown' }),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_TOKEN'
      );
    });
  });

  describe('decodeJwt (Signature-less inspection)', () => {
    it('decodes header, payload, and signature without requiring secret or key', () => {
      const token = mintMockJwt(
        { sub: 'decode-user', role: 'Member' },
        DEFAULT_SECRET,
        'HS256',
        { header: { customHeader: 'xyz' } }
      );

      const decoded = decodeJwt(token);
      assert.strictEqual(decoded.header.alg, 'HS256');
      assert.strictEqual(decoded.header.customHeader, 'xyz');
      assert.strictEqual(decoded.payload.sub, 'decode-user');
      assert.strictEqual(decoded.payload.role, 'Member');
      assert.ok(typeof decoded.signature === 'string');
    });

    it('decodes expired or invalid-signature tokens without error', () => {
      const token = mintMockJwt({ sub: 'expired', exp: 1 }, DEFAULT_SECRET, 'HS256');
      const decoded = decodeJwt(token);
      assert.strictEqual(decoded.payload.sub, 'expired');
    });

    it('throws ERR_INVALID_TOKEN if token is malformed', () => {
      assert.throws(
        () => decodeJwt('header.only-two-parts'),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_TOKEN'
      );
      assert.throws(
        () => decodeJwt(''),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_TOKEN'
      );
    });
  });

  describe('synthesizePersonaJwt - Matrix Personas & Claims Synthesis', () => {
    it('returns null for anonymous persona or null input', () => {
      assert.strictEqual(synthesizePersonaJwt(null, {}, DEFAULT_SECRET), null);
      assert.strictEqual(synthesizePersonaJwt(undefined, {}, DEFAULT_SECRET), null);

      const anonymousPersona = {
        role: null,
        tenantId: null,
        userId: null,
        isAnonymous: true,
      };
      assert.strictEqual(synthesizePersonaJwt(anonymousPersona, {}, DEFAULT_SECRET), null);
    });

    it('synthesizes valid token for INTRA_TENANT_ALLOW persona', () => {
      const allowPersona = {
        role: 'OrgAdmin',
        tenantId: 'tenant-alpha',
        userId: 'user-tenant-alpha-orgadmin',
        isAnonymous: false,
      };

      const jwtConfig = {
        role_claim: 'role',
        tenant_claim: 'tenant_id',
        user_id_claim: 'sub',
        algorithm: 'HS256',
        issuer: 'gatekeeper-ci',
        audience: 'gatekeeper-target',
      };

      const token = synthesizePersonaJwt(allowPersona, jwtConfig, DEFAULT_SECRET);
      assert.ok(typeof token === 'string');

      const verified = verifyJwt(token, DEFAULT_SECRET, {
        issuer: 'gatekeeper-ci',
        audience: 'gatekeeper-target',
      });
      assert.strictEqual(verified.valid, true);
      assert.strictEqual(verified.payload.role, 'OrgAdmin');
      assert.strictEqual(verified.payload.tenant_id, 'tenant-alpha');
      assert.strictEqual(verified.payload.sub, 'user-tenant-alpha-orgadmin');
    });

    it('synthesizes valid token for INTRA_TENANT_DENY persona', () => {
      const denyPersona = {
        role: 'Viewer',
        tenantId: 'tenant-alpha',
        userId: 'user-tenant-alpha-viewer',
        isAnonymous: false,
      };

      const token = synthesizePersonaJwt(denyPersona, { role_claim: 'role' }, DEFAULT_SECRET);
      const verified = verifyJwt(token, DEFAULT_SECRET);
      assert.strictEqual(verified.valid, true);
      assert.strictEqual(verified.payload.role, 'Viewer');
      assert.strictEqual(verified.payload.tenant_id, 'tenant-alpha');
      assert.strictEqual(verified.payload.sub, 'user-tenant-alpha-viewer');
    });

    it('synthesizes valid token for CROSS_TENANT_ATTACK persona with secondary tenant context', () => {
      const attackerPersona = {
        role: 'OrgAdmin',
        tenantId: 'tenant-beta',
        userId: 'attacker-tenant-beta-orgadmin',
        isAnonymous: false,
      };

      const token = synthesizePersonaJwt(attackerPersona, { role_claim: 'role' }, DEFAULT_SECRET);
      const verified = verifyJwt(token, DEFAULT_SECRET);
      assert.strictEqual(verified.valid, true);
      assert.strictEqual(verified.payload.role, 'OrgAdmin');
      assert.strictEqual(verified.payload.tenant_id, 'tenant-beta');
      assert.strictEqual(verified.payload.sub, 'attacker-tenant-beta-orgadmin');
    });

    it('formats plural role claim (roles) as an array by default', () => {
      const persona = { role: 'Member', tenantId: 'tenant-alpha', userId: 'user-1', isAnonymous: false };
      const token = synthesizePersonaJwt(persona, { role_claim: 'roles' }, DEFAULT_SECRET);
      const decoded = decodeJwt(token);
      assert.deepStrictEqual(decoded.payload.roles, ['Member']);
    });

    it('formats groups and permissions plural claims as arrays', () => {
      const persona = { role: 'Auditor', tenantId: 'tenant-1', userId: 'user-1', isAnonymous: false };
      const tokenGroups = synthesizePersonaJwt(persona, { role_claim: 'groups' }, DEFAULT_SECRET);
      assert.deepStrictEqual(decodeJwt(tokenGroups).payload.groups, ['Auditor']);

      const tokenPerms = synthesizePersonaJwt(persona, { role_claim: 'permissions' }, DEFAULT_SECRET);
      assert.deepStrictEqual(decodeJwt(tokenPerms).payload.permissions, ['Auditor']);
    });

    it('supports dot-notation nested role claims (e.g. realm_access.roles)', () => {
      const persona = { role: 'Member', tenantId: 'tenant-1', userId: 'user-1', isAnonymous: false };
      const token = synthesizePersonaJwt(
        persona,
        { role_claim: 'realm_access.roles', tenant_claim: 'custom.org_id', user_id_claim: 'identity.uid' },
        DEFAULT_SECRET
      );

      const decoded = decodeJwt(token);
      assert.deepStrictEqual(decoded.payload.realm_access, { roles: ['Member'] });
      assert.strictEqual(decoded.payload.custom.org_id, 'tenant-1');
      assert.strictEqual(decoded.payload.identity.uid, 'user-1');
    });

    it('supports options.asArray: true forcing array format even for singular claim name', () => {
      const persona = { role: 'Member', tenantId: 'tenant-1', userId: 'user-1', isAnonymous: false };
      const token = synthesizePersonaJwt(
        persona,
        { role_claim: 'role' },
        DEFAULT_SECRET,
        { asArray: true }
      );
      const decoded = decodeJwt(token);
      assert.deepStrictEqual(decoded.payload.role, ['Member']);
    });

    it('synthesizes token using AuthPolicy instance directly', () => {
      const policy = new AuthPolicy({
        version: '1',
        roles: ['SuperAdmin', 'OrgAdmin'],
        adjacencyList: new Map([['SuperAdmin', ['OrgAdmin']], ['OrgAdmin', []]]),
        transitiveRoles: new Map([['SuperAdmin', new Set(['SuperAdmin', 'OrgAdmin'])], ['OrgAdmin', new Set(['OrgAdmin'])]]),
        authorizedCallers: new Map([['OrgAdmin', new Set(['SuperAdmin', 'OrgAdmin'])], ['SuperAdmin', new Set(['SuperAdmin'])]]),
        jwt: {
          algorithm: 'HS256',
          role_claim: 'role',
          tenant_claim: 'org_id',
          user_id_claim: 'sub',
          issuer: 'policy-issuer',
        },
      });

      const persona = { role: 'SuperAdmin', tenantId: 'corp-1', userId: 'usr-9', isAnonymous: false };
      const token = synthesizePersonaJwt(persona, policy, DEFAULT_SECRET);
      const verified = verifyJwt(token, DEFAULT_SECRET);
      assert.strictEqual(verified.payload.role, 'SuperAdmin');
      assert.strictEqual(verified.payload.org_id, 'corp-1');
      assert.strictEqual(verified.payload.iss, 'policy-issuer');
    });

    it('synthesizes token using asymmetric RSA keypair', () => {
      const keyPair = generateKeyPair('RS256');
      const persona = { role: 'SuperAdmin', tenantId: 't-1', userId: 'u-1', isAnonymous: false };
      const token = synthesizePersonaJwt(
        persona,
        { algorithm: 'RS256', role_claim: 'role' },
        keyPair.privateKey
      );

      const verified = verifyJwt(token, keyPair.publicKey);
      assert.strictEqual(verified.header.alg, 'RS256');
      assert.strictEqual(verified.payload.role, 'SuperAdmin');
    });
  });

  describe('Error Conditions', () => {
    it('throws ERR_UNSUPPORTED_ALGORITHM when minting with unsupported algorithm', () => {
      assert.throws(
        () => mintMockJwt({ sub: 'user-1' }, DEFAULT_SECRET, 'none'),
        (err) => err instanceof JwtError && err.code === 'ERR_UNSUPPORTED_ALGORITHM'
      );
      assert.throws(
        () => mintMockJwt({ sub: 'user-1' }, DEFAULT_SECRET, 'HS128'),
        (err) => err instanceof JwtError && err.code === 'ERR_UNSUPPORTED_ALGORITHM'
      );
    });

    it('throws ERR_INVALID_INPUT if mintMockJwt has no secret or private key', () => {
      assert.throws(
        () => mintMockJwt({ sub: 'user-1' }, null, 'HS256'),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_INPUT'
      );
    });

    it('throws ERR_INVALID_INPUT if verifyJwt has no secret or public key', () => {
      const token = mintMockJwt({ sub: 'user-1' }, DEFAULT_SECRET, 'HS256');
      assert.throws(
        () => verifyJwt(token, null),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_INPUT'
      );
    });

    it('throws ERR_UNSUPPORTED_ALGORITHM if algorithm is restricted by options.algorithms', () => {
      const token = mintMockJwt({ sub: 'user-1' }, DEFAULT_SECRET, 'HS256');
      assert.throws(
        () => verifyJwt(token, DEFAULT_SECRET, { algorithms: ['RS256'] }),
        (err) => err instanceof JwtError && err.code === 'ERR_UNSUPPORTED_ALGORITHM'
      );
    });

    it('throws ERR_INVALID_TOKEN if token has fewer or more than 3 segments', () => {
      assert.throws(
        () => verifyJwt('only.two', DEFAULT_SECRET),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_TOKEN'
      );
      assert.throws(
        () => verifyJwt('one.two.three.four', DEFAULT_SECRET),
        (err) => err instanceof JwtError && err.code === 'ERR_INVALID_TOKEN'
      );
    });
  });
});

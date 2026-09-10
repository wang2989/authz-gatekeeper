import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import YAML from 'yaml';

/**
 * Custom error class for OpenAPI specification ingestion and validation failures.
 */
export class InvalidSpecError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidSpecError';
    this.code = 'ERR_INVALID_SPEC';
    this.exitCode = 2;
  }
}

/**
 * Deserializes raw string content into an in-memory object using JSON or YAML parsing.
 * 
 * @param {string} rawText - Raw file or response body content
 * @param {string} [formatHint] - Optional format hint ('json', 'yaml', 'yml')
 * @returns {object} Parsed JavaScript object
 * @throws {InvalidSpecError} If parsing as both JSON and YAML fails
 */
export function parseSpecContent(rawText, formatHint = null) {
  if (typeof rawText !== 'string' || rawText.trim().length === 0) {
    throw new InvalidSpecError('OpenAPI specification content is empty.');
  }

  const trimmed = rawText.trim();

  // If hinted as YAML, attempt YAML parsing first
  if (formatHint === 'yaml' || formatHint === 'yml') {
    try {
      const parsed = YAML.parse(rawText);
      if (parsed && typeof parsed === 'object') {
        return parsed;
      }
    } catch {
      // Fall through to try JSON
    }
  }

  // Attempt JSON parsing first for standard JSON or untyped files
  try {
    return JSON.parse(rawText);
  } catch (jsonErr) {
    // If JSON parsing fails, attempt YAML parsing
    try {
      const parsedYaml = YAML.parse(rawText);
      if (parsedYaml && typeof parsedYaml === 'object') {
        return parsedYaml;
      }
    } catch (yamlErr) {
      throw new InvalidSpecError(
        `Failed to parse OpenAPI specification as JSON or YAML.\n` +
        `  • JSON Parse Error: ${jsonErr.message}\n` +
        `  • YAML Parse Error: ${yamlErr.message}`
      );
    }

    throw new InvalidSpecError(
      `Failed to parse OpenAPI specification as JSON or YAML: Parsed content must be an object.`
    );
  }
}

/**
 * Validates the parsed object to ensure it conforms to essential OpenAPI / Swagger structural requirements.
 * 
 * @param {any} specObj - Parsed specification object
 * @param {string} [sourceName='spec'] - Name or path of source for error reporting
 * @returns {object} Validated OpenAPI document
 * @throws {InvalidSpecError} If the specification is missing mandatory fields
 */
export function validateOpenApiStructure(specObj, sourceName = 'spec') {
  if (!specObj || typeof specObj !== 'object' || Array.isArray(specObj)) {
    throw new InvalidSpecError(`Invalid OpenAPI document in "${sourceName}": root must be an object.`);
  }

  // 1. Version declaration validation
  const hasOpenApi = typeof specObj.openapi === 'string';
  const hasSwagger = typeof specObj.swagger === 'string';

  if (!hasOpenApi && !hasSwagger) {
    throw new InvalidSpecError(
      `Invalid OpenAPI specification in "${sourceName}": missing "openapi" version declaration (e.g., openapi: "3.0.3").`
    );
  }

  if (hasOpenApi) {
    const versionMatch = specObj.openapi.match(/^3\.\d+(\.\d+)?/);
    if (!versionMatch) {
      throw new InvalidSpecError(
        `Unsupported OpenAPI version "${specObj.openapi}" in "${sourceName}". Gatekeeper requires OpenAPI 3.0+ (or Swagger 2.0).`
      );
    }
  } else if (hasSwagger) {
    if (specObj.swagger !== '2.0') {
      throw new InvalidSpecError(
        `Unsupported Swagger version "${specObj.swagger}" in "${sourceName}". Gatekeeper requires OpenAPI 3.0+ (or Swagger 2.0).`
      );
    }
  }

  // 2. Info object validation
  if (!specObj.info || typeof specObj.info !== 'object' || Array.isArray(specObj.info)) {
    throw new InvalidSpecError(
      `Invalid OpenAPI specification in "${sourceName}": missing required "info" object.`
    );
  }

  const { title, version } = specObj.info;
  if (!title || typeof title !== 'string' || title.trim().length === 0) {
    throw new InvalidSpecError(
      `Invalid OpenAPI specification in "${sourceName}": "info.title" is required and must be a non-empty string.`
    );
  }

  if (typeof version !== 'string' || version.trim().length === 0) {
    throw new InvalidSpecError(
      `Invalid OpenAPI specification in "${sourceName}": "info.version" is required and must be a non-empty string.`
    );
  }

  // 3. Paths object validation
  if (!specObj.paths || typeof specObj.paths !== 'object' || Array.isArray(specObj.paths)) {
    throw new InvalidSpecError(
      `Invalid OpenAPI specification in "${sourceName}": missing required "paths" object.`
    );
  }

  return specObj;
}

/**
 * Ingests, parses, and validates an OpenAPI 3.0+ specification from a local file path or remote HTTP(S) URL.
 * 
 * @param {string} specPathOrUrl - Local filesystem path or remote HTTP URL
 * @returns {Promise<object>} Standardized and validated OpenAPI specification object
 * @throws {InvalidSpecError} On unreadable files, network failures, syntax errors, or schema validation failures
 */
export async function loadOpenApiSpec(specPathOrUrl) {
  if (!specPathOrUrl || typeof specPathOrUrl !== 'string' || specPathOrUrl.trim().length === 0) {
    throw new InvalidSpecError('OpenAPI specification path or URL must be provided.');
  }

  const trimmedPath = specPathOrUrl.trim();
  const isHttpUrl = trimmedPath.startsWith('http://') || trimmedPath.startsWith('https://');

  let rawContent;
  let formatHint = null;

  if (trimmedPath.endsWith('.yaml') || trimmedPath.endsWith('.yml')) {
    formatHint = 'yaml';
  } else if (trimmedPath.endsWith('.json')) {
    formatHint = 'json';
  }

  if (isHttpUrl) {
    let response;
    try {
      response = await fetch(trimmedPath, {
        method: 'GET',
        headers: {
          Accept: 'application/json, application/yaml, text/yaml, text/plain, */*',
        },
      });
    } catch (err) {
      throw new InvalidSpecError(
        `Failed to fetch remote OpenAPI specification from "${trimmedPath}": ${err.message}`
      );
    }

    if (!response.ok) {
      throw new InvalidSpecError(
        `Failed to load remote OpenAPI specification from "${trimmedPath}": HTTP ${response.status} ${response.statusText}`
      );
    }

    rawContent = await response.text();
  } else {
    const resolvedPath = resolve(process.cwd(), trimmedPath);
    try {
      rawContent = await readFile(resolvedPath, 'utf-8');
    } catch (err) {
      throw new InvalidSpecError(
        `OpenAPI specification file not found or unreadable: "${trimmedPath}" (${err.message})`
      );
    }
  }

  const parsed = parseSpecContent(rawContent, formatHint);
  return validateOpenApiStructure(parsed, trimmedPath);
}


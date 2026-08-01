#!/usr/bin/env node
/* GraphSmith minimal JSON Schema (2020-12 subset) validator —
 * scripts/schema-validate.js. Lane D, v0.5.0 Wave 1.
 *
 * WHY THIS EXISTS INSTEAD OF `ajv`. The Lane D brief asks for adapter
 * definitions to be validated against schemas/host-adapter.schema.json using
 * Ajv2020 specifically (bare `ajv` defaults to draft-07 and would silently
 * under-validate a 2020-12 `$schema`). That means adding `ajv` as a
 * devDependency. This repo's package.json has NO `dependencies` key AND NO
 * `devDependencies` key at all — every existing script (verify.js, gate.js,
 * reconcile.js, ...) is hand-rolled zero-dependency CommonJS, including
 * scripts that already do their own hand-rolled JSON/contract validation
 * (see e.g. scripts/manifest.js's own manifest-shape checks). There is no
 * precedent anywhere in this repo for a dev-only dependency exception to the
 * project's zero-dependency ethos — the rule really is zero, full stop, not
 * "zero at runtime." Introducing `ajv` (a real, non-trivial dependency tree)
 * purely to validate four small, hand-authored JSON files against one frozen
 * schema would be the first dependency this repo has ever taken on, for a
 * job well within reach of ~150 lines of plain JS. JUDGMENT CALL: this file
 * hand-rolls the SUBSET of JSON Schema 2020-12 that
 * schemas/host-adapter.schema.json actually uses (type, enum, pattern,
 * required, properties/additionalProperties, items, allOf[].if/then with a
 * `const` condition) rather than adding ajv. It is not a general-purpose
 * JSON Schema validator and does not claim to be one — see the keyword list
 * below. If a future schema needs a keyword this file does not implement,
 * that is a loud `Unsupported schema keyword` throw, never a silent
 * under-validation.
 *
 * Deterministic, zero-LLM, zero-dependency CommonJS, Node >= 18. No network
 * calls, no clocks/randomness anywhere in this file.
 *
 * SUPPORTED KEYWORDS (deliberately narrow — the exact set
 * schemas/host-adapter.schema.json uses, confirmed by reading that schema
 * directly): type, enum, pattern, required, properties, additionalProperties
 * (only the literal `false` form), items (single schema, not tuple-form),
 * allOf (each entry either a plain schema, or an {if, then} pair where `if`
 * is restricted to `{properties: {<key>: {const: <value>}}}`).
 * UNSUPPORTED (any use throws loudly rather than being silently ignored):
 * anyOf, oneOf, not, $ref, if/else, minimum/maximum, minItems/maxItems,
 * uniqueItems, const outside of an allOf-if, propertyNames, dependentSchemas.
 */
"use strict";

const SUPPORTED_KEYWORDS = new Set([
  "$schema", "$id", "title", "description", "$comment", // metadata, ignored
  "type", "enum", "pattern", "required", "properties",
  "additionalProperties", "items", "allOf", "const",
]);

function typeOf(instance) {
  if (instance === null) return "null";
  if (Array.isArray(instance)) return "array";
  return typeof instance; // "object" | "string" | "number" | "boolean" | "undefined"
}

function checkType(instance, expected) {
  const actual = typeOf(instance);
  if (expected === "integer") return actual === "number" && Number.isInteger(instance);
  return actual === expected;
}

/** Throws if `schema` (or any nested subschema reachable without going
 * through an unsupported keyword) uses a keyword this validator does not
 * implement. Walked once per top-level validate() call, not memoized --
 * these schemas are tiny (single-digit KB) and this only runs in tests/
 * generation, never a hot path. */
function assertOnlySupportedKeywords(schema, ctxPath) {
  if (schema === null || typeof schema !== "object") return;
  if (Array.isArray(schema)) {
    for (let i = 0; i < schema.length; i++) assertOnlySupportedKeywords(schema[i], `${ctxPath}[${i}]`);
    return;
  }
  for (const key of Object.keys(schema)) {
    if (key === "if" || key === "then" || key === "staticValue") {
      // "if"/"then" are only valid inside an allOf entry, handled by the
      // "allOf" branch below (which walks entry.if/entry.then explicitly),
      // not walked generically here. "staticValue" is a
      // host-adapter-schema-specific property name (a schema of type {}
      // with no keywords, i.e. "anything goes"), not a JSON Schema
      // keyword -- skip descending into it as a keyword name. "const" is a
      // real, generically-supported keyword (see SUPPORTED_KEYWORDS /
      // validate()) and falls through to the normal check below -- it is
      // NOT limited to appearing inside allOf.if (host-adapter.schema.json
      // itself uses a bare {"const": ...} inside an allOf[].then).
      continue;
    }
    if (!SUPPORTED_KEYWORDS.has(key)) {
      throw new Error(`schema-validate: unsupported schema keyword "${key}" at ${ctxPath} -- refusing to under-validate silently`);
    }
    const val = schema[key];
    if (key === "properties" && val && typeof val === "object") {
      for (const propName of Object.keys(val)) assertOnlySupportedKeywords(val[propName], `${ctxPath}.properties.${propName}`);
    } else if (key === "items") {
      assertOnlySupportedKeywords(val, `${ctxPath}.items`);
    } else if (key === "allOf" && Array.isArray(val)) {
      for (let i = 0; i < val.length; i++) {
        const entry = val[i];
        if (entry && typeof entry === "object") {
          if ("if" in entry) assertOnlySupportedKeywords(entry.if, `${ctxPath}.allOf[${i}].if`);
          if ("then" in entry) assertOnlySupportedKeywords(entry.then, `${ctxPath}.allOf[${i}].then`);
          const rest = Object.assign({}, entry);
          delete rest.if;
          delete rest.then;
          delete rest.$comment;
          assertOnlySupportedKeywords(rest, `${ctxPath}.allOf[${i}]`);
        }
      }
    }
  }
}

/** Boolean match used only to evaluate an allOf[].if -- restricted to the
 * one shape host-adapter.schema.json actually uses:
 * {"properties": {"<key>": {"const": <value>}}}. Throws if the `if` uses
 * anything outside that shape. */
function matchesIf(instance, ifSchema, ctxPath) {
  if (!ifSchema || typeof ifSchema !== "object") return true;
  const keys = Object.keys(ifSchema);
  if (keys.length !== 1 || keys[0] !== "properties") {
    throw new Error(`schema-validate: unsupported "if" shape at ${ctxPath} -- only {"properties": {...}} is implemented`);
  }
  const props = ifSchema.properties;
  for (const propName of Object.keys(props)) {
    const propSchema = props[propName];
    const propKeys = Object.keys(propSchema);
    if (propKeys.length !== 1 || propKeys[0] !== "const") {
      throw new Error(`schema-validate: unsupported "if.properties.${propName}" shape at ${ctxPath} -- only {"const": ...} is implemented`);
    }
    if (typeOf(instance) !== "object" || instance === null) return false;
    if (instance[propName] !== propSchema.const) return false;
  }
  return true;
}

/** Validates `instance` against `schema`, returning an array of error
 * strings (empty = valid). `ctxPath` is a JSON-Pointer-ish path used only
 * for readable error messages. */
function validate(instance, schema, ctxPath) {
  ctxPath = ctxPath || "$";
  assertOnlySupportedKeywords(schema, ctxPath);
  const errors = [];

  if (Object.prototype.hasOwnProperty.call(schema, "type")) {
    if (!checkType(instance, schema.type)) {
      errors.push(`${ctxPath}: expected type "${schema.type}", got "${typeOf(instance)}"`);
      return errors; // further checks on the wrong shape would just be noise
    }
  }

  if (Object.prototype.hasOwnProperty.call(schema, "enum")) {
    const ok = schema.enum.some((v) => v === instance);
    if (!ok) errors.push(`${ctxPath}: value ${JSON.stringify(instance)} not in enum ${JSON.stringify(schema.enum)}`);
  }

  if (Object.prototype.hasOwnProperty.call(schema, "const")) {
    if (instance !== schema.const) {
      errors.push(`${ctxPath}: value ${JSON.stringify(instance)} does not equal const ${JSON.stringify(schema.const)}`);
    }
  }

  if (Object.prototype.hasOwnProperty.call(schema, "pattern") && typeof instance === "string") {
    const re = new RegExp(schema.pattern);
    if (!re.test(instance)) errors.push(`${ctxPath}: value ${JSON.stringify(instance)} does not match pattern ${schema.pattern}`);
  }

  if (Array.isArray(schema.required) && typeOf(instance) === "object") {
    for (const key of schema.required) {
      if (!Object.prototype.hasOwnProperty.call(instance, key)) {
        errors.push(`${ctxPath}: missing required property "${key}"`);
      }
    }
  }

  if (schema.properties && typeOf(instance) === "object") {
    for (const key of Object.keys(schema.properties)) {
      if (Object.prototype.hasOwnProperty.call(instance, key)) {
        errors.push(...validate(instance[key], schema.properties[key], `${ctxPath}.${key}`));
      }
    }
  }

  if (schema.additionalProperties === false && typeOf(instance) === "object") {
    const allowed = new Set(Object.keys(schema.properties || {}));
    for (const key of Object.keys(instance)) {
      if (!allowed.has(key)) errors.push(`${ctxPath}: additional property "${key}" not allowed`);
    }
  }

  if (schema.items && typeOf(instance) === "array") {
    for (let i = 0; i < instance.length; i++) {
      errors.push(...validate(instance[i], schema.items, `${ctxPath}[${i}]`));
    }
  }

  if (Array.isArray(schema.allOf)) {
    for (let i = 0; i < schema.allOf.length; i++) {
      const entry = schema.allOf[i];
      const entryPath = `${ctxPath}.allOf[${i}]`;
      if (entry && typeof entry === "object" && ("if" in entry)) {
        if (matchesIf(instance, entry.if, entryPath)) {
          errors.push(...validate(instance, entry.then || {}, entryPath));
        }
      } else {
        errors.push(...validate(instance, entry, entryPath));
      }
    }
  }

  return errors;
}

module.exports = {
  validate,
  assertOnlySupportedKeywords,
};

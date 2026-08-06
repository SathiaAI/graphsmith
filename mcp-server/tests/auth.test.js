"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { isAuthenticated, extractBearerToken } = require("../src/auth.js");

test("extractBearerToken parses a well-formed header", () => {
  assert.equal(extractBearerToken("Bearer abc123"), "abc123");
  assert.equal(extractBearerToken("bearer abc123"), "abc123"); // case-insensitive scheme
});

test("extractBearerToken returns null for missing/malformed headers", () => {
  assert.equal(extractBearerToken(undefined), null);
  assert.equal(extractBearerToken(""), null);
  assert.equal(extractBearerToken("Basic abc123"), null);
  assert.equal(extractBearerToken("abc123"), null);
});

test("isAuthenticated: correct token authenticates", () => {
  assert.equal(isAuthenticated("Bearer supersecrettoken123", "supersecrettoken123"), true);
});

test("isAuthenticated: wrong token is refused", () => {
  assert.equal(isAuthenticated("Bearer wrongtoken", "supersecrettoken123"), false);
});

test("isAuthenticated: missing header is refused", () => {
  assert.equal(isAuthenticated(undefined, "supersecrettoken123"), false);
});

test("isAuthenticated: no expected token configured -> fail closed (refuse everything)", () => {
  assert.equal(isAuthenticated("Bearer anything", ""), false);
  assert.equal(isAuthenticated("Bearer anything", undefined), false);
  assert.equal(isAuthenticated("Bearer anything", null), false);
});

test("isAuthenticated: does not throw on differing-length tokens (no crash on probe attempts)", () => {
  assert.doesNotThrow(() => isAuthenticated("Bearer x", "a-much-longer-real-token-value"));
  assert.equal(isAuthenticated("Bearer x", "a-much-longer-real-token-value"), false);
});

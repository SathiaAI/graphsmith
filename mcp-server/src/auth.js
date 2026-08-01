"use strict";

const crypto = require("crypto");

/* Per-request bearer-token auth for any non-stdio (network) transport.
 *
 * Per the frozen Lane C design and the Wave 1 kickoff's adversarial-test
 * requirement: this is a HARD, STRUCTURAL requirement, not a documented
 * best practice a caller can forget to wire up. There is no code path in
 * httpTransport.js that reaches the JSON-RPC dispatcher without first
 * passing isAuthenticated() -- see httpTransport.js, where the check runs
 * before the request body is even read, let alone parsed or dispatched.
 *
 * This is the exact gap clarity-agent shipped (zero auth on sse/
 * streamable-http transports) and this module exists specifically so that
 * mistake is not repeated here.
 */

function extractBearerToken(authorizationHeader) {
  if (!authorizationHeader || typeof authorizationHeader !== "string") return null;
  const match = /^Bearer\s+(.+)$/i.exec(authorizationHeader.trim());
  return match ? match[1] : null;
}

/* Constant-time-ish comparison. crypto.timingSafeEqual throws on
 * length mismatch, so unequal-length inputs are treated as unequal without
 * ever calling it on mismatched buffers (which would throw, not return
 * false, and could turn a routine unauthenticated probe into a 500). */
function timingSafeEqual(a, b) {
  const aBuf = Buffer.from(String(a), "utf8");
  const bBuf = Buffer.from(String(b), "utf8");
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

/* isAuthenticated is fail-closed in BOTH directions:
 *   - no expectedToken configured  -> refuse every request, no exceptions.
 *     A network transport must never silently fall back to "no auth
 *     configured means allow everything."
 *   - no/malformed Authorization header, or a non-matching token -> refuse.
 * Only a present, well-formed "Bearer <token>" header whose token matches
 * expectedToken byte-for-byte returns true. */
function isAuthenticated(authorizationHeader, expectedToken) {
  if (!expectedToken || typeof expectedToken !== "string" || expectedToken.length === 0) {
    return false;
  }
  const presented = extractBearerToken(authorizationHeader);
  if (!presented) return false;
  return timingSafeEqual(presented, expectedToken);
}

module.exports = { extractBearerToken, isAuthenticated, timingSafeEqual };

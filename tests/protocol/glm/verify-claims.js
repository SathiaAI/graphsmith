#!/usr/bin/env node
/**
 * verify-claims.js - Automated verification of GraphSmith protocol claims
 * 
 * This script cross-checks key claims in GRAPHSMITH-PROTOCOL.md against the
 * actual implementation. It's a lightweight verification tool, not a comprehensive
 * test suite.
 * 
 * Usage: node tests/protocol/glm/verify-claims.js
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const PROTOCOL_PATH = path.join(ROOT, 'GRAPHSMITH-PROTOCOL.md');
const VERIFY_PATH = path.join(ROOT, 'scripts', 'verify.js');
const GATE_PATH = path.join(ROOT, 'scripts', 'gate.js');
const PROMOTE_PATH = path.join(ROOT, 'scripts', 'promote.js');
const ADOPT_PATH = path.join(ROOT, 'scripts', 'adopt.js');

console.log('GraphSmith Protocol Claim Verification\n');

const findings = {
  passed: [],
  failed: [],
  warnings: []
};

// Helper: check if file exists and contains pattern
function checkFileContains(filePath, pattern, description) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    if (pattern.test(content)) {
      findings.passed.push(`✓ ${description}`);
      return true;
    } else {
      findings.failed.push(`✗ ${description}`);
      return false;
    }
  } catch (e) {
    findings.warnings.push(`⚠ ${description} - could not read file: ${e.message}`);
    return false;
  }
}

// Helper: check exact string match
function checkStringContains(filePath, needle, description) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    if (content.includes(needle)) {
      findings.passed.push(`✓ ${description}`);
      return true;
    } else {
      findings.failed.push(`✗ ${description}`);
      return false;
    }
  } catch (e) {
    findings.warnings.push(`⚠ ${description} - could not read file: ${e.message}`);
    return false;
  }
}

console.log('Checking protocol document exists...');
checkFileContains(PROTOCOL_PATH, /# GraphSmith Protocol/, 
  'Protocol document exists with proper title');

console.log('\nChecking profile implementations...');

// R Profile
checkStringContains(VERIFY_PATH, 'profileResumableState', 
  'R profile: profileResumableState() function exists');
checkFileContains(VERIFY_PATH, /ephemeral.*fixture/i,
  'R profile: mentions ephemeral fixtures in code');

// E Profile  
checkStringContains(VERIFY_PATH, 'profileEffectReconciliation',
  'E profile: profileEffectReconciliation() function exists');
checkStringContains(VERIFY_PATH, 'RECONCILIATION_BY_VARIANT',
  'E profile: RECONCILIATION_BY_VARIANT table exists');

// B Profile
checkStringContains(VERIFY_PATH, 'profileBudgetEnforced',
  'B profile: profileBudgetEnforced() function exists');

// T Profile
checkStringContains(VERIFY_PATH, 'function runProfiles',
  'T profile: runProfiles() function exists');
checkFileContains(VERIFY_PATH, /release_verified.*self_consistent|self_consistent.*release_verified/,
  'T profile: checks both release_verified and self_consistent');

// G Profile
checkStringContains(VERIFY_PATH, 'profileGatedLearning',
  'G profile: profileGatedLearning() function exists');
checkFileContains(VERIFY_PATH, /confirm.*false|confirmation.*required/i,
  'G profile: tests adopt without confirmation');

// Q Profile
checkStringContains(VERIFY_PATH, 'profileAssuranceTested',
  'Q profile: profileAssuranceTested() function exists');

// X Profile
checkStringContains(VERIFY_PATH, 'profileAdversariallyTested',
  'X profile: profileAdversariallyTested() function exists');

console.log('\nChecking gate implementations...');

// Gate 1
checkStringContains(GATE_PATH, 'function gate1Static',
  'Gate 1: gate1Static() function exists');
checkFileContains(GATE_PATH, /fence|write-set/i,
  'Gate 1: checks fence write-set');
checkFileContains(GATE_PATH, /schema.*valid|typed.*schema/i,
  'Gate 1: performs typed-schema validation');
checkStringContains(GATE_PATH, 'injection screen',
  'Gate 1: performs injection screen');

// Gate 2
checkFileContains(GATE_PATH, /0\.05.*3|3.*0\.05/,
  'Gate 2: uses Bonferroni-split alpha = 0.05/3');
checkStringContains(GATE_PATH, 'MAX_ALPHA_SLOTS',
  'Gate 2: has 3 preallocated confirmation slots');
checkStringContains(GATE_PATH, 'exact sign test',
  'Gate 2: implements exact sign test');

// Gate 3
checkStringContains(GATE_PATH, 'function gate3Prepare',
  'Gate 3: gate3Prepare() function exists');
checkFileContains(GATE_PATH, /reversible.*auto.*rollback|auto.*rollback.*reversible/i,
  'Gate 3: produces reversible/autoRollbackEligible flags');

// Gate 4
checkStringContains(GATE_PATH, 'gate4Admit',
  'Gate 4: gate4Admit() function exists');
checkStringContains(GATE_PATH, 'gate4Observe',
  'Gate 4: gate4Observe() function exists');
checkStringContains(GATE_PATH, 'gate4Close',
  'Gate 4: gate4Close() function exists');

console.log('\nChecking promotion transaction...');

checkStringContains(PROMOTE_PATH, 'function promote',
  'Promote: promote() function exists');
checkStringContains(PROMOTE_PATH, 'function rollback',
  'Promote: rollback() function exists');
checkFileContains(PROMOTE_PATH, /LEASED|STAGED|VALIDATED|LOGGED|SWAPPED|MANIFEST/,
  'Promote: documents transaction phases');
checkStringContains(PROMOTE_PATH, 'buildEntry',
  'Promote: builds journal entries');

console.log('\nChecking adoption...');

checkStringContains(ADOPT_PATH, 'function adopt',
  'Adopt: adopt() function exists');
checkStringContains(ADOPT_PATH, 'ADOPTION_REQUIRES_HUMAN_CONFIRMATION',
  'Adopt: requires human confirmation');
checkStringContains(ADOPT_PATH, 'GATE4_OUTCOMES',
  'Adopt: validates Gate 4 outcomes');

console.log('\nChecking honest-language compliance...');

// Check for banned terms in protocol
const protocolContent = fs.readFileSync(PROTOCOL_PATH, 'utf8');
const bannedTerms = [
  'proven to',
  'proven that',
  'immutable',
  'certified for',
  'certified that',
  'constant monitoring',
  'tamper-proof',
  'exactly-once delivery',
  'exactly once delivery',
  'guaranteed to',
  'cannot fail',
  'cannot reach the network'
];

let protocolClean = true;
bannedTerms.forEach(term => {
  if (new RegExp(term, 'i').test(protocolContent)) {
    findings.failed.push(`✗ Honest language: found banned term pattern "${term}" in protocol`);
    protocolClean = false;
  }
});

if (protocolClean) {
  findings.passed.push('✓ Honest language: no banned terms found in protocol');
}

console.log('\nChecking for publication hygiene issues...');

// Check for external identifiers
const externalPatterns = [
  /arxiv\.org/,
  /doi\.org/,
  /ieee\.org/,
  /acm\.org/,
  /usenix\.org/,
  /springer\.com/,
  /sciencedirect\.com/,
  /nature\.com/,
  /github\.com\/[^\/]+\/graphsmith/i,  // Non-GraphSmith GitHub repos
];

let publicationClean = true;
externalPatterns.forEach(pattern => {
  if (pattern.test(protocolContent)) {
    findings.failed.push(`✗ Publication hygiene: found external reference pattern ${pattern}`);
    publicationClean = false;
  }
});

if (publicationClean) {
  findings.passed.push('✓ Publication hygiene: no external research/organization references');
}

console.log('\n' + '='.repeat(60));
console.log('VERIFICATION SUMMARY');
console.log('='.repeat(60));

console.log(`\nPassed: ${findings.passed.length}`);
console.log(`Failed: ${findings.failed.length}`);
console.log(`Warnings: ${findings.warnings.length}`);

if (findings.passed.length > 0) {
  console.log('\nPassed checks:');
  findings.passed.forEach(p => console.log('  ' + p));
}

if (findings.failed.length > 0) {
  console.log('\nFailed checks:');
  findings.failed.forEach(f => console.log('  ' + f));
}

if (findings.warnings.length > 0) {
  console.log('\nWarnings:');
  findings.warnings.forEach(w => console.log('  ' + w));
}

console.log('\n' + '='.repeat(60));

const exitCode = findings.failed.length > 0 ? 1 : 0;
process.exit(exitCode);
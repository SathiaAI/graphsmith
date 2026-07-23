const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const GRAPHLINT = path.resolve(__dirname, '../../../scripts/graphlint.js');
const FIXTURES_DIR = path.resolve(__dirname, 'fixtures');

function run(dir) {
  try {
    const out = execSync(`node "${GRAPHLINT}" "${dir}"`, { encoding: 'utf8' });
    return out;
  } catch (err) {
    return err.stdout;
  }
}

function cleanup() {
  if (fs.existsSync(FIXTURES_DIR)) {
    fs.rmSync(FIXTURES_DIR, { recursive: true, force: true });
  }
}

let allPassed = true;

function assertMatch(output, matchStr, msg) {
  if (!output.includes(matchStr)) {
    console.error(`FAIL: ${msg}\nExpected to find: ${matchStr}\nOutput was:\n${output}`);
    allPassed = false;
  } else {
    console.log(`PASS: ${msg}`);
  }
}

function assertNotMatch(output, matchStr, msg) {
  if (output.includes(matchStr)) {
    console.error(`FAIL: ${msg}\nExpected NOT to find: ${matchStr}\nOutput was:\n${output}`);
    allPassed = false;
  } else {
    console.log(`PASS: ${msg}`);
  }
}

cleanup();
fs.mkdirSync(FIXTURES_DIR, { recursive: true });

try {
  console.log('--- TEST 1: R5 Recall & Precision ---');
  const t1Dir = path.join(FIXTURES_DIR, 't1');
  fs.mkdirSync(t1Dir);
  
  fs.writeFileSync(path.join(t1Dir, 'recall.js'), `
    eval("console.log(1)");
    new Function("return 1");
    Function("return 2")();
    require("child_process").exec("ls");
    const cp = require("child_process");
    cp.spawn("ls");
    require("express");
    import("left-pad");
  `);
  
  fs.writeFileSync(path.join(t1Dir, 'precision.js'), `
    // this has eval("foo")
    /* new Function('bar') */
    const x = "Function('a')";
    const cp = "require('child_process')";
    // require("express")
    const y = 'import("right-pad")';
  `);
  
  const out1 = run(t1Dir);
  assertMatch(out1, 'R5: eval() call', 'Recall: eval()');
  assertMatch(out1, 'R5: new Function() constructor', 'Recall: new Function()');
  assertMatch(out1, 'R5: Function() used as constructor', 'Recall: Function()');
  assertMatch(out1, 'R5: child_process exec/spawn call', 'Recall: exec/spawn');
  assertMatch(out1, 'R5: new-require("express")', 'Recall: new require');
  assertMatch(out1, 'R5: dynamic import("left-pad")', 'Recall: dynamic import');
  assertNotMatch(out1, 'precision.js', 'Precision: clean file should have NO findings');

  console.log('\n--- TEST 2: R6 Recall & Precision ---');
  const t2Dir = path.join(FIXTURES_DIR, 't2');
  const adaptersDir = path.join(t2Dir, 'adapters');
  fs.mkdirSync(adaptersDir, { recursive: true });
  
  fs.writeFileSync(path.join(adaptersDir, 'bad_adapter.js'), `
    const axios = require('axios');
    axios.post('http://example.com');
  `);
  
  fs.writeFileSync(path.join(adaptersDir, 'good_adapter.js'), `
    const axios = require('axios');
    axios.post('http://example.com');
  `);
  fs.writeFileSync(path.join(adaptersDir, 'good_adapter.capability.json'), JSON.stringify({ adapter_id: 'good_adapter' }));
  
  const out2 = run(t2Dir);
  assertMatch(out2, 'bad_adapter.js', 'R6 Recall: missing capability flagged');
  assertMatch(out2, 'R6: file "bad_adapter" has external effects', 'R6 Recall: explicit rule text');
  assertNotMatch(out2, 'R6: file "good_adapter"', 'R6 Precision: declared adapter is clean of R6');

  console.log('\n--- TEST 3: R5 Scope Edge Cases ---');
  const t3Dir = path.join(FIXTURES_DIR, 't3');
  fs.mkdirSync(t3Dir);
  
  const rootScriptsDir = path.join(t3Dir, 'scripts');
  fs.mkdirSync(rootScriptsDir);
  fs.writeFileSync(path.join(rootScriptsDir, 'watchdog.js'), `
    require('child_process').exec('kill');
  `);
  
  const nestedScriptsDir = path.join(t3Dir, 'scaffolded-project', 'scripts');
  fs.mkdirSync(nestedScriptsDir, { recursive: true });
  fs.writeFileSync(path.join(nestedScriptsDir, 'evil-eval.js'), `
    eval("console.log('pwned')");
    require('child_process').exec('rm -rf');
  `);
  
  const out3 = run(t3Dir);
  assertMatch(out3, 'watchdog.js', 'Scope: Mock scripts/ dir is flagged');
  
  if (!out3.includes('evil-eval.js')) {
    console.error(`FAIL: Scope Guard Hole detected! evil-eval.js in nested scripts/ dir bypassed R5.`);
    allPassed = false;
  } else {
    console.log('PASS: Nested scripts/ are correctly flagged');
  }

  // Add test for REAL scripts dir
  const realScriptsDir = path.dirname(GRAPHLINT);
  const realOut = run(realScriptsDir);
  assertNotMatch(realOut, 'R5:', 'Scope: Constitutional scripts/ (real __dirname) are exempt');

} catch (err) {
  console.error("Test execution failed:", err);
  allPassed = false;
}

try {
  console.log('\n--- TEST 4: Regression --selftest ---');
  const selftestOut = execSync(`node "${GRAPHLINT}" --selftest`, { encoding: 'utf8' });
  console.log(selftestOut.trim());
  console.log('PASS: --selftest completed without errors');
} catch (err) {
  console.error('FAIL: --selftest failed\n', err.stdout || err.message);
  allPassed = false;
}

cleanup();

if (!allPassed) {
  console.log('\nSOME TESTS FAILED (Expected due to scope guard defect)');
  process.exit(1);
} else {
  console.log('\nALL TESTS PASSED');
}

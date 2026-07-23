const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

const evalenv = require('../../../scripts/evalenv.js');

function runTests() {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'gemini-evalenv-tests-'));
  let anyFailed = false;

  function report(name, pass, reason = '') {
    const status = pass ? 'PASS' : 'FAIL';
    console.log(`[${status}] ${name}${reason ? ' - ' + reason : ''}`);
    if (!pass) anyFailed = true;
  }

  try {
    // ---- ATTACK 1: Isolation / escape ----
    const srcDir1 = path.join(tmpRoot, 'src1');
    fs.mkdirSync(srcDir1, { recursive: true });
    
    // Create forbidden dirs
    fs.mkdirSync(path.join(srcDir1, '.git'));
    fs.writeFileSync(path.join(srcDir1, '.git', 'config'), 'fake');
    fs.mkdirSync(path.join(srcDir1, '.graphsmith'));
    fs.writeFileSync(path.join(srcDir1, '.graphsmith', 'state'), 'fake');
    fs.mkdirSync(path.join(srcDir1, 'node_modules'));
    fs.writeFileSync(path.join(srcDir1, 'node_modules', 'mod'), 'fake');

    // Create external target for symlink (directory)
    const externalTarget = path.join(tmpRoot, 'external_secret_dir');
    fs.mkdirSync(externalTarget);
    fs.writeFileSync(path.join(externalTarget, 'TOP_SECRET.txt'), 'TOP SECRET');

    let symlinksCreated = false;
    try {
      // Create symlink pointing outside
      const srcSymlinkPath = path.join(srcDir1, 'link_out');
      fs.symlinkSync(externalTarget, srcSymlinkPath, 'junction');

      // Create .. traversal symlink
      const srcTraversalPath = path.join(srcDir1, 'link_up');
      fs.symlinkSync('..\\..', srcTraversalPath, 'junction');
      symlinksCreated = true;
    } catch (e) {
      console.log('Skipping symlink creation due to OS limitations:', e.message);
    }

    process.env.NODE_PATH = '/real/tree/path';

    const std1 = evalenv.create('standard', { sourceDir: srcDir1, tmpRoot });
    
    const copyDir1 = std1.dir;
    
    let isolationPass = true;
    let isolationReason = [];
    
    if (fs.existsSync(path.join(copyDir1, '.git'))) {
      isolationPass = false; isolationReason.push('.git was copied');
    }
    if (fs.existsSync(path.join(copyDir1, '.graphsmith'))) {
      isolationPass = false; isolationReason.push('.graphsmith was copied');
    }
    if (fs.existsSync(path.join(copyDir1, 'node_modules'))) {
      isolationPass = false; isolationReason.push('node_modules was copied');
    }
    if (symlinksCreated) {
      if (fs.existsSync(path.join(copyDir1, 'link_out'))) {
        isolationPass = false; isolationReason.push('external symlink was copied');
      }
      if (fs.existsSync(path.join(copyDir1, 'link_up'))) {
        isolationPass = false; isolationReason.push('traversal symlink was copied');
      }
      if (std1.copyReport.symlinks_skipped.length !== 2) {
        isolationPass = false; isolationReason.push(`symlinks_skipped should be 2, but was ${std1.copyReport.symlinks_skipped.length}`);
      }
    }
    
    if (std1.env.NODE_PATH) {
      isolationPass = false; isolationReason.push('NODE_PATH leaked');
    }
    
    report('Attack 1: Isolation/Escape', isolationPass, isolationReason.join(', '));
    std1.destroy();


    // ---- ATTACK 2: Secret-scrub ----
    const srcDir2 = path.join(tmpRoot, 'src2');
    fs.mkdirSync(srcDir2, { recursive: true });
    
    process.env.FAKE_SECRET = 'secret123';
    process.env.AWS_ACCESS_KEY_ID = 'aws123';
    process.env.OPENROUTER_API_KEY = 'openrouter123';
    process.env.PATH_SNEAKY = 'sneaky';
    process.env.PATHEXT_FAKE = 'fake';
    process.env.PATHEXT = 'legit';

    const std2 = evalenv.create('standard', { sourceDir: srcDir2, tmpRoot });
    
    let secretPass = true;
    let secretReason = [];
    if ('FAKE_SECRET' in std2.env) { secretPass = false; secretReason.push('FAKE_SECRET leaked'); }
    if ('AWS_ACCESS_KEY_ID' in std2.env) { secretPass = false; secretReason.push('AWS_ACCESS_KEY_ID leaked'); }
    if ('OPENROUTER_API_KEY' in std2.env) { secretPass = false; secretReason.push('OPENROUTER_API_KEY leaked'); }
    if ('PATH_SNEAKY' in std2.env) { secretPass = false; secretReason.push('PATH_SNEAKY leaked'); }
    if ('PATHEXT_FAKE' in std2.env) { secretPass = false; secretReason.push('PATHEXT_FAKE leaked'); }
    if (!('PATHEXT' in std2.env)) { secretPass = false; secretReason.push('PATHEXT missing'); }
    
    report('Attack 2: Secret-scrub default-deny', secretPass, secretReason.join(', '));
    std2.destroy();


    // ---- ATTACK 3: Container-required B10 ----
    const srcDir3 = path.join(tmpRoot, 'src3');
    fs.mkdirSync(srcDir3, { recursive: true });
    const std3 = evalenv.create('standard', { sourceDir: srcDir3, tmpRoot });
    
    let containerPass = true;
    let containerReason = [];
    
    try {
      std3.runUntrustedCode();
      containerPass = false; containerReason.push('Standard profile allowed runUntrustedCode');
    } catch (e) {
      if (e.code !== 'CONTAINER_REQUIRED') {
        containerPass = false; containerReason.push('Wrong error code for std runUntrustedCode: ' + e.code);
      }
    }
    
    try {
      evalenv.requireContainer(std3);
      containerPass = false; containerReason.push('requireContainer allowed standard profile');
    } catch (e) {
      if (e.code !== 'CONTAINER_REQUIRED') {
        containerPass = false; containerReason.push('Wrong error code for requireContainer: ' + e.code);
      }
    }
    
    const containerNoRuntime = evalenv.create('container', { 
      sourceDir: srcDir3, 
      tmpRoot,
      envOverrideForDetection: { PATH: '/empty/path/no/runtime' }
    });
    
    if (containerNoRuntime.available !== false) {
      containerPass = false; containerReason.push('Container without runtime reported as available');
    }
    
    try {
      containerNoRuntime.runUntrustedCode();
      containerPass = false; containerReason.push('Container without runtime allowed runUntrustedCode');
    } catch (e) {
      if (e.code !== 'CONTAINER_UNAVAILABLE') {
        containerPass = false; containerReason.push('Wrong error code for container no-runtime runUntrustedCode: ' + e.code);
      }
    }
    
    report('Attack 3: Container-required B10', containerPass, containerReason.join(', '));
    std3.destroy();
    
    
    // ---- ATTACK 4: Budgets + destroy ----
    const srcDir4 = path.join(tmpRoot, 'src4');
    fs.mkdirSync(srcDir4, { recursive: true });
    fs.writeFileSync(path.join(srcDir4, 'f1.txt'), '1');
    fs.writeFileSync(path.join(srcDir4, 'f2.txt'), '2');
    fs.writeFileSync(path.join(srcDir4, 'f3.txt'), '3');
    
    let budgetPass = true;
    let budgetReason = [];
    
    try {
      evalenv.create('standard', { 
        sourceDir: srcDir4, 
        tmpRoot,
        budgets: { max_files: 2 }
      });
      budgetPass = false; budgetReason.push('Allowed creation exceeding max_files budget');
    } catch (e) {
      if (e.code !== 'BUDGET_BREACH') {
        budgetPass = false; budgetReason.push('Wrong error code for budget breach: ' + e.code);
      }
    }
    
    const dirsInTmp = fs.readdirSync(tmpRoot).filter(x => x.startsWith('graphsmith-evalenv-'));
    if (dirsInTmp.length > 0) {
      budgetPass = false; budgetReason.push('Leftover directory after budget breach');
    }
    
    const std4 = evalenv.create('standard', { sourceDir: srcDir4, tmpRoot });
    const dir4 = std4.dir;
    std4.destroy();
    if (fs.existsSync(dir4)) {
      budgetPass = false; budgetReason.push('Directory still exists after destroy');
    }
    
    try {
      std4.destroy(); // double destroy
    } catch (e) {
      budgetPass = false; budgetReason.push('Double destroy threw an error: ' + e.message);
    }
    
    report('Attack 4: Budgets + destroy', budgetPass, budgetReason.join(', '));
    
    
    // ---- ATTACK 5: Honest claims ----
    const srcDir5 = path.join(tmpRoot, 'src5');
    fs.mkdirSync(srcDir5, { recursive: true });
    const std5 = evalenv.create('standard', { sourceDir: srcDir5, tmpRoot });
    
    let honestPass = true;
    let honestReason = [];
    
    if (std5.claims.confidentiality !== false) {
      honestPass = false; honestReason.push('Over-claimed confidentiality');
    }
    if (std5.claims.network_containment !== false) {
      honestPass = false; honestReason.push('Over-claimed network_containment');
    }
    
    report('Attack 5: Honest claims', honestPass, honestReason.join(', '));
    std5.destroy();
    
    // ---- ATTACK 6: Determinism ----
    const srcDir6 = path.join(tmpRoot, 'src6');
    fs.mkdirSync(srcDir6, { recursive: true });
    fs.writeFileSync(path.join(srcDir6, 'f1.txt'), '1');
    const std6a = evalenv.create('standard', { sourceDir: srcDir6, tmpRoot });
    const std6b = evalenv.create('standard', { sourceDir: srcDir6, tmpRoot });
    
    let determinismPass = true;
    let determinismReason = [];
    
    if (std6a.claims.isolation_level !== std6b.claims.isolation_level) {
      determinismPass = false; determinismReason.push('claims.isolation_level differ');
    }
    if (std6a.isolation.isolated !== std6b.isolation.isolated) {
      determinismPass = false; determinismReason.push('isolation.isolated differ');
    }
    if (std6a.budgets.values.max_wall_time_ms !== std6b.budgets.values.max_wall_time_ms) {
      determinismPass = false; determinismReason.push('budgets.values.max_wall_time_ms differ');
    }
    
    report('Attack 6: Determinism', determinismPass, determinismReason.join(', '));
    std6a.destroy();
    std6b.destroy();

    // ---- ATTACK 7: Defect Discovery: Budget bypass with empty directories ----
    const srcDir7 = path.join(tmpRoot, 'src7');
    fs.mkdirSync(srcDir7, { recursive: true });
    
    // Create 5 empty directories
    for (let i = 0; i < 5; i++) {
      fs.mkdirSync(path.join(srcDir7, `empty_dir_${i}`));
    }
    
    let defect1Pass = true;
    let defect1Reason = [];
    
    try {
      const std7 = evalenv.create('standard', { 
        sourceDir: srcDir7, 
        tmpRoot,
        budgets: { max_files: 2 } 
      });
      defect1Pass = false; defect1Reason.push('Budget max_files bypassed using empty directories');
      std7.destroy();
    } catch (e) {
      if (e.code !== 'BUDGET_BREACH') {
        defect1Pass = false; defect1Reason.push('Wrong error code for budget breach: ' + e.code);
      }
    }
    
    report('Attack 7: Defect Discovery (Budget Bypass)', defect1Pass, defect1Reason.join(', '));

    // ---- ATTACK 8: Defect Discovery: spawnOptions.env leakage in container ----
    // This is hard to test directly because testing runUntrustedCode needs a real container runtime.
    // We will just report it as a structural defect in FINDINGS.md.

  } catch (e) {
    console.error('Unhandled error during tests:', e);
    anyFailed = true;
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
  
  if (anyFailed) {
    process.exit(1);
  }
}

runTests();
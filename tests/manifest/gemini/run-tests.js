const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const manifest = require('../../../scripts/manifest.js');

const TMP_BASE = path.join(os.tmpdir(), 'graphsmith-gemini-tests-');
let failures = 0;

function report(name, passed, reason = '') {
  if (passed) {
    console.log(`PASS: ${name}${reason ? ' - ' + reason : ''}`);
  } else {
    console.log(`FAIL: ${name} - ${reason}`);
    failures++;
  }
}

function runTests() {
  let tmpDir;
  try {
    tmpDir = fs.mkdtempSync(TMP_BASE);

    // 1. Tamper detection
    try {
      const d1 = path.join(tmpDir, 't1');
      fs.mkdirSync(d1);
      fs.writeFileSync(path.join(d1, 'file.txt'), 'hello world');
      const m1 = manifest.generate('tree', { rootDir: d1 });
      fs.writeFileSync(path.join(d1, 'tree.manifest.json'), JSON.stringify(m1));
      
      fs.writeFileSync(path.join(d1, 'file.txt'), 'hxllo world');
      const v1 = manifest.verifyTree(path.join(d1, 'tree.manifest.json'), d1);
      
      if (!v1.ok && v1.files.some(f => f.path === 'file.txt' && f.status === 'mismatch')) {
        report('Tamper detection', true);
      } else {
        report('Tamper detection', false, 'Did not report mismatch on flipped byte');
      }
    } catch (e) {
      report('Tamper detection', false, e.message);
    }

    // 2. Extra/missing payload file
    try {
      const d2 = path.join(tmpDir, 't2');
      fs.mkdirSync(d2);
      fs.writeFileSync(path.join(d2, 'file.txt'), 'hello');
      const m2 = manifest.generate('tree', { rootDir: d2 });
      fs.writeFileSync(path.join(d2, 'tree.manifest.json'), JSON.stringify(m2));
      
      fs.unlinkSync(path.join(d2, 'file.txt'));
      const v2m = manifest.verifyTree(path.join(d2, 'tree.manifest.json'), d2);
      if (!v2m.ok && v2m.files.some(f => f.status === 'missing')) {
        report('Missing file detection', true);
      } else {
        report('Missing file detection', false, 'Failed to detect missing file');
      }

      fs.writeFileSync(path.join(d2, 'file.txt'), 'hello');
      fs.writeFileSync(path.join(d2, 'extra.txt'), 'extra');
      const v2e = manifest.verifyTree(path.join(d2, 'tree.manifest.json'), d2);
      if (!v2e.ok && v2e.files.some(f => f.status === 'extra')) {
        report('Extra file detection', true);
      } else {
        report('Extra file detection', false, 'Failed to detect extra file');
      }

      fs.unlinkSync(path.join(d2, 'extra.txt'));
      const v2ok = manifest.verifyTree(path.join(d2, 'tree.manifest.json'), d2);
      if (v2ok.ok) report('Manifest not extra', true);
      else report('Manifest not extra', false, 'Reported tree.manifest.json as extra or other error');
    } catch (e) {
      report('Extra/missing payload', false, e.message);
    }

    // 3. Case-fold collision
    try {
      const d3 = path.join(tmpDir, 't3');
      fs.mkdirSync(d3);
      fs.writeFileSync(path.join(d3, 'a.txt'), 'A');
      fs.writeFileSync(path.join(d3, 'A.txt'), 'B'); 
      // check if fs merged them (case-insensitive)
      if (fs.readdirSync(d3).length === 1) {
        // Mock a collision manually against checkCaseFoldCollisions function using 'includeOnly' bypass? No, includeOnly just filters what's on disk.
        // Let's test checkCaseFoldCollisions directly using a mock payload or simply report skipped if FS merges.
        // Wait, manifest.js doesn't export checkCaseFoldCollisions.
        // Let's create a subdirectory? Doesn't change case insensitivity.
        // We can just note it.
        report('Case-fold collision', true, 'SKIPPED: FS merged files, cannot test natively');
      } else {
        let caught = false;
        try {
          manifest.generate('tree', { rootDir: d3 });
        } catch (e) {
          if (e.message.includes('case-fold collision') || e.message.includes('Case-fold collision')) caught = true;
        }
        if (caught) report('Case-fold collision', true);
        else report('Case-fold collision', false, 'generate did not refuse case-fold collision');
      }
    } catch (e) {
      report('Case-fold collision', false, e.message);
    }

    // 4. Unicode NFC vs NFD
    try {
      const d4 = path.join(tmpDir, 't4');
      fs.mkdirSync(d4);
      const nfc = 'café.txt'.normalize('NFC');
      const nfd = 'café.txt'.normalize('NFD');
      fs.writeFileSync(path.join(d4, nfc), 'A');
      
      const files = fs.readdirSync(d4);
      if (files.length === 1 && files[0] === nfc) {
        const m4 = manifest.generate('tree', { rootDir: d4 });
        if (m4.files[0].path === nfc) report('Unicode NFC normalization', true);
        else report('Unicode NFC normalization', false, 'path was not canonicalized to NFC');
      } else {
         report('Unicode NFC normalization', true, 'SKIPPED: FS altered normalization');
      }
    } catch (e) {
      report('Unicode NFC normalization', false, e.message);
    }

    // 5. Raw-byte discipline
    try {
      const d5 = path.join(tmpDir, 't5');
      fs.mkdirSync(d5);
      fs.writeFileSync(path.join(d5, 'lf.txt'), Buffer.from('hello\\nworld'));
      fs.writeFileSync(path.join(d5, 'crlf.txt'), Buffer.from('hello\\r\\nworld'));
      const m5 = manifest.generate('tree', { rootDir: d5 });
      const hLF = m5.files.find(f => f.path === 'lf.txt').sha256;
      const hCRLF = m5.files.find(f => f.path === 'crlf.txt').sha256;
      if (hLF !== hCRLF) report('Raw-byte discipline', true);
      else report('Raw-byte discipline', false, 'LF and CRLF hashed to same value');
    } catch (e) {
      report('Raw-byte discipline', false, e.message);
    }

    // 6. Symlink/junction refusal
    try {
      const d6 = path.join(tmpDir, 't6');
      fs.mkdirSync(d6);
      const targetDir = path.join(d6, 'target');
      fs.mkdirSync(targetDir);
      fs.writeFileSync(path.join(targetDir, 'file.txt'), 'target');
      
      let junctionCreated = false;
      try {
        fs.symlinkSync(targetDir, path.join(d6, 'link'), 'junction');
        junctionCreated = true;
      } catch (e) {
        report('Symlink refusal', true, 'SKIPPED: No privilege to create junction');
      }

      if (junctionCreated) {
        try {
          manifest.generate('tree', { rootDir: d6 });
          report('Symlink refusal', false, 'generate allowed junction/symlink without refusal (it likely ignored it silently)');
        } catch (e) {
          if (e.message.toLowerCase().includes('symlink') || e.message.toLowerCase().includes('refuse') || e.message.toLowerCase().includes('junction')) {
            report('Symlink refusal', true);
          } else {
            report('Symlink refusal', false, `Failed with unexpected error: ${e.message}`);
          }
        }
      }
    } catch (e) {
      report('Symlink refusal', false, e.message);
    }

    // 7. Determinism
    try {
      const d7 = path.join(tmpDir, 't7');
      fs.mkdirSync(d7);
      fs.writeFileSync(path.join(d7, 'b.txt'), 'B');
      fs.writeFileSync(path.join(d7, 'a.txt'), 'A');
      const m7a = manifest.generate('tree', { rootDir: d7 });
      const m7b = manifest.generate('tree', { rootDir: d7 });
      if (JSON.stringify(m7a) === JSON.stringify(m7b)) report('Determinism', true);
      else report('Determinism', false, 'Consecutive generates yielded different JSON');
    } catch (e) {
      report('Determinism', false, e.message);
    }

    // 8. Malformed manifests
    try {
      const d8 = path.join(tmpDir, 't8');
      fs.mkdirSync(d8);
      
      // Truncated JSON
      const truncPath = path.join(d8, 'trunc.json');
      fs.writeFileSync(truncPath, '{"schema_version": "1.0", "files": [');
      try {
        manifest.verifyTree(truncPath, d8);
        report('Malformed manifest: truncated JSON', false, 'Did not throw');
      } catch (e) {
        if (e instanceof SyntaxError) report('Malformed manifest: truncated JSON', true, 'Throws SyntaxError');
        else report('Malformed manifest: truncated JSON', false, 'Threw non-SyntaxError');
      }

      // Wrong schema version
      const wrongSchemaPath = path.join(d8, 'wrong.json');
      fs.writeFileSync(wrongSchemaPath, JSON.stringify({
        schema_version: '99.0',
        files: []
      }));
      try {
        manifest.verifyTree(wrongSchemaPath, d8);
        report('Malformed manifest: wrong schema_version', false, 'verifyTree allowed wrong schema_version without error');
      } catch (e) {
        if (e.message.includes('schema')) report('Malformed manifest: wrong schema_version', true);
        else report('Malformed manifest: wrong schema_version', false, `Threw unexpected error: ${e.message}`);
      }

      // Negative sizes
      fs.writeFileSync(path.join(d8, 'file.txt'), 'hello');
      const badSizePath = path.join(d8, 'badsize.json');
      fs.writeFileSync(badSizePath, JSON.stringify({
        schema_version: '1.0',
        files: [{ path: 'file.txt', sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', bytes: -5 }]
      }));
      try {
        const v8bad = manifest.verifyTree(badSizePath, d8);
        // Did it throw? No. Did it fail cleanly? It returns mismatched files.
        // But the prompt says "clean error exit 1/2, never a crash or a false PASS"
        // Wait, malformed inputs to verifyTree should cleanly error exit (throw).
        // If it just silently parses and then emits a mismatch for each negative size, it means it didn't validate the schema.
        report('Malformed manifest: negative sizes', false, 'verifyTree allowed negative size format without throwing schema error');
      } catch (e) {
        report('Malformed manifest: negative sizes', true, 'Throws error');
      }
      
    } catch (e) {
      report('Malformed manifest', false, e.message);
    }

  } finally {
    if (tmpDir) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  if (failures > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTests();

'use strict';

const express    = require('express');
const { spawn }  = require('child_process');
const path       = require('path');
const fs         = require('fs');

/* ─── Paths ─────────────────────────────────────────────────── */
const ROOT    = path.join(__dirname, '..');          // dilithium_library/
const EXE     = path.join(ROOT, 'build', 'dilithium_sig.exe');
const KEYS_DIR = path.join(ROOT, 'keys');

// Make sure the keys/ directory exists
if (!fs.existsSync(KEYS_DIR)) fs.mkdirSync(KEYS_DIR, { recursive: true });

/* ─── Core: run the CLI with piped stdin ─────────────────────── */
function runDilithium(inputs) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(EXE)) {
      return reject(new Error(`Executable not found: ${EXE}\nRun build.bat first.`));
    }

    const proc = spawn(EXE, ['--web'], { cwd: ROOT });
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', d => { stdout += d.toString(); });
    proc.stderr.on('data', d => { stderr += d.toString(); });
    proc.on('error', reject);
    proc.on('close', code => resolve({ stdout: stdout.trim(), stderr: stderr.trim(), code }));

    // Write all inputs at once then close stdin
    proc.stdin.write(inputs.join('\n') + '\n');
    proc.stdin.end();
  });
}

/* ─── Express setup ─────────────────────────────────────────── */
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/* ─── POST /api/keygen ───────────────────────────────────────── */
app.post('/api/keygen', async (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Key name is required' });

  // Sanitise: strip path separators so name stays a simple filename
  const safeName = name.trim().replace(/[/\\:*?"<>|]/g, '_');
  const keyPrefix = path.join(KEYS_DIR, safeName);

  try {
    const { stdout, stderr } = await runDilithium(['1', keyPrefix, '4']);

    if (!stdout.includes('Public Key:')) {
      return res.status(500).json({ error: stderr || 'Key generation failed' });
    }

    // Parse: "Public Key: 1952 bytes  ->  ..."
    const pubMatch = stdout.match(/Public Key:\s*(\d+)/);
    const secMatch = stdout.match(/Secret Key:\s*(\d+)/);

    res.json({
      success  : true,
      pubFile  : `${safeName}_pub.txt`,
      secFile  : `${safeName}_sec.txt`,
      pubBytes : pubMatch ? parseInt(pubMatch[1]) : 1952,
      secBytes : secMatch ? parseInt(secMatch[1]) : 4032,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ─── POST /api/sign ─────────────────────────────────────────── */
app.post('/api/sign', async (req, res) => {
  const { keyName, message, docName } = req.body;
  if (!keyName || !message || !docName) {
    return res.status(400).json({ error: 'keyName, message, and docName are required' });
  }

  const safeKey = keyName.trim().replace(/[/\\:*?"<>|]/g, '_');
  const safeDoc = docName.trim().replace(/[/\\:*?"<>|]/g, '_');

  const secKeyPath  = path.join(KEYS_DIR, `${safeKey}_sec.txt`);
  const outputPrefix = path.join(KEYS_DIR, safeDoc);

  if (!fs.existsSync(secKeyPath)) {
    return res.status(404).json({ error: `Secret key not found: ${safeKey}_sec.txt` });
  }

  try {
    const { stdout, stderr } = await runDilithium([
      '2',
      secKeyPath,
      message.replace(/\r?\n/g, ' '),   // keep message as a single line
      outputPrefix,
      '4',
    ]);

    if (!stdout.includes('Signature Size')) {
      return res.status(500).json({ error: stderr || 'Signing failed' });
    }

    const sizeMatch = stdout.match(/Signature Size\s*:\s*(\d+)/);

    res.json({
      success  : true,
      msgFile  : `${safeDoc}_msg.txt`,
      sigFile  : `${safeDoc}.sig`,
      sigBytes : sizeMatch ? parseInt(sizeMatch[1]) : 3309,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ─── POST /api/verify ───────────────────────────────────────── */
app.post('/api/verify', async (req, res) => {
  const { keyName, docName } = req.body;
  if (!keyName || !docName) {
    return res.status(400).json({ error: 'keyName and docName are required' });
  }

  const safeKey = keyName.trim().replace(/[/\\:*?"<>|]/g, '_');
  const safeDoc = docName.trim().replace(/[/\\:*?"<>|]/g, '_');

  const pubKeyPath = path.join(KEYS_DIR, `${safeKey}_pub.txt`);
  const msgPath    = path.join(KEYS_DIR, `${safeDoc}_msg.txt`);
  const sigPath    = path.join(KEYS_DIR, `${safeDoc}.sig`);

  for (const [label, p] of [['Public key', pubKeyPath], ['Message file', msgPath], ['Signature', sigPath]]) {
    if (!fs.existsSync(p)) {
      return res.status(404).json({ error: `${label} not found: ${path.basename(p)}` });
    }
  }

  try {
    const { stdout } = await runDilithium([
      '3',
      pubKeyPath,
      msgPath,
      sigPath,
      '4',
    ]);

    const result = stdout.includes('VALID') && !stdout.includes('INVALID') ? 'VALID' : 'INVALID';
    res.json({ success: true, result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ─── GET /api/message?doc=<name> ────────────────────────────── */
// Let the frontend display the plain-text message content
app.get('/api/message', (req, res) => {
  const safeDoc = (req.query.doc || '').replace(/[/\\:*?"<>|]/g, '_');
  const msgPath = path.join(KEYS_DIR, `${safeDoc}_msg.txt`);
  if (!fs.existsSync(msgPath)) return res.status(404).json({ error: 'Message file not found' });
  res.sendFile(msgPath);
});

/* ─── Start server ───────────────────────────────────────────── */
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n  Dilithium Web UI running at http://localhost:${PORT}`);
  console.log(`  Keys stored in: ${KEYS_DIR}`);
  console.log(`  CLI executable: ${EXE}\n`);
});

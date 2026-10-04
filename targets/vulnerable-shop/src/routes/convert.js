import { Router } from 'express';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * A stand-in for a real document/format converter binary (think `convert`,
 * `ffmpeg`, `pandoc`). Bundling it keeps the demo runnable anywhere, with no
 * external tools to install -- the vulnerability is in how we invoke it, not in
 * what it does.
 */
const CONVERTER = path.resolve(__dirname, '../../tools/convert-cli.js');

/**
 * POST /convert   { "format": "pdf", "input": "report.txt" }
 *
 * VULN #3 — command injection.
 *
 * `format` and `input` from the JSON body are concatenated into a shell command
 * that is handed to exec(), which runs it through a shell. Shell metacharacters
 * in either field therefore start a second command.
 *
 * Exploit:
 *   { "format": "pdf", "input": "report.txt & echo PATCHPROOF_PWNED" }
 *   { "format": "pdf", "input": "report.txt & whoami" }
 *
 * ('&' works as a command separator in both cmd.exe and sh; ';' works on sh.)
 */
export function createConvertRouter() {
  const router = Router();

  router.post('/convert', (req, res) => {
    const body = req.body ?? {};
    const format = typeof body.format === 'string' && body.format ? body.format : 'pdf';
    const input = typeof body.input === 'string' ? body.input : '';

    if (!input) {
      return res.status(400).json({ error: 'input is required' });
    }

    // VULN #3: user input interpolated into a shell command. A safe version
    // would avoid the shell entirely:
    //   execFile(process.execPath, [CONVERTER, '--format', format, '--input', input])
    const command = [CONVERTER, '--format', format, '--input', input];

    return execFile(process.execPath, command, { timeout: 5000 }, (error, stdout, stderr) => {
      if (error && !stdout) {
        return res.status(500).json({ error: error.message, stderr });
      }
      return res.json({
        format,
        input,
        command: `node ${CONVERTER} --format ${format} --input ${input}`, // For output consistency
        output: stdout,
        stderr,
        exitCode: error ? (error.code ?? 1) : 0,
      });
    });
  });

  return router;
}

/**
 * Entry point: starts the vulnerable target on $PORT (default 3000).
 *
 * DO NOT DEPLOY. This app is intentionally insecure; run it only inside the
 * sandbox container or on a machine you control.
 */
import { createApp } from './app.js';

const PORT = Number(process.env.PORT) || 3000;

createApp().listen(PORT, () => {
  console.log(`[vulnerable-shop] listening on http://0.0.0.0:${PORT}`);
});

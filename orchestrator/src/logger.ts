/**
 * Simple leveled logger. Kept dependency-free on purpose.
 * Levels: debug < info < warn < error
 */
import { config } from './config.js';

const LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export type LogLevel = (typeof LEVELS)[number];

const threshold = LEVELS.indexOf(config.logLevel as LogLevel);

function emit(level: LogLevel, scope: string, message: string, meta?: unknown): void {
  if (LEVELS.indexOf(level) < Math.max(threshold, 0)) return;
  const stamp = new Date().toISOString();
  const line = `${stamp} [${level.toUpperCase()}] (${scope}) ${message}`;
  if (level === 'error') console.error(line, meta ?? '');
  else if (level === 'warn') console.warn(line, meta ?? '');
  else console.log(line, meta ?? '');
}

export function createLogger(scope: string) {
  return {
    debug: (m: string, meta?: unknown) => emit('debug', scope, m, meta),
    info: (m: string, meta?: unknown) => emit('info', scope, m, meta),
    warn: (m: string, meta?: unknown) => emit('warn', scope, m, meta),
    error: (m: string, meta?: unknown) => emit('error', scope, m, meta),
  };
}

export type Logger = ReturnType<typeof createLogger>;

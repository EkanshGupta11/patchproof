/**
 * Read-only-ish access to the target app's source tree.
 *
 * Every path is resolved and checked to stay inside the target directory, so a
 * hallucinating agent cannot make us read or overwrite something else.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { config } from '../config.js';

const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', '.patchproof']);

/** Directories an agent may never write into, even inside the target. */
const PROTECTED_DIRS = new Set(['node_modules', '.git', 'dist', '.patchproof']);

export function targetRoot(): string {
  return path.resolve(process.cwd(), config.target.path);
}

/** Thrown when a path is rejected. Carries a reason the agents can act on. */
export class PathEscapeError extends Error {
  constructor(
    readonly requested: string,
    readonly reason: string,
  ) {
    super(`Refusing path "${requested}": ${reason}`);
    this.name = 'PathEscapeError';
  }
}

/**
 * Resolve a caller-supplied relative path and prove it lands inside the target.
 *
 * Rejects, in order of how easily they are hit:
 *   - absolute paths and Windows drive/UNC paths (nothing legitimate needs these)
 *   - `..` traversal, in either separator style
 *   - NUL bytes and control characters, which truncate paths in some syscalls
 *   - symlinks pointing outside the repo, checked after resolution so a link
 *     planted in the repo cannot be used as a bridge
 *
 * Returns the absolute path, which callers should use rather than re-deriving it.
 */
export async function resolveInsideTarget(relativePath: string): Promise<string> {
  const root = targetRoot();
  const withSep = root.endsWith(path.sep) ? root : root + path.sep;

  if (typeof relativePath !== 'string' || relativePath.length === 0) {
    throw new PathEscapeError(String(relativePath), 'path is empty');
  }

  // NUL truncates the string in several native calls, turning "a\0/../../etc"
  // into something that validates cleanly but resolves elsewhere.
  if (/[\u0000-\u001f]/.test(relativePath)) {
    throw new PathEscapeError(relativePath, 'path contains control characters or NUL');
  }

  if (path.isAbsolute(relativePath) || /^[a-zA-Z]:/.test(relativePath) || relativePath.startsWith('\\\\')) {
    throw new PathEscapeError(relativePath, 'path must be relative to the target repo');
  }

  // Normalise separators, then check for traversal on the normalised form so a
  // backslash on Windows cannot smuggle a `..` past the check.
  const normalised = relativePath.replace(/\\/g, '/');
  if (normalised.split('/').includes('..')) {
    throw new PathEscapeError(relativePath, 'path contains ".." and escapes the target repo');
  }

  const resolved = path.resolve(root, normalised);
  if (resolved !== root && !resolved.startsWith(withSep)) {
    throw new PathEscapeError(relativePath, 'resolved path is outside the target repo');
  }

  // A symlink inside the repo can still point out of it, so compare the real
  // location too. For a file that does not exist yet (we are about to create it)
  // the lexical check above is the best available and stands on its own.
  try {
    const realResolved = await fs.realpath(resolved);
    if (realResolved !== root && !realResolved.startsWith(withSep)) {
      throw new PathEscapeError(
        relativePath,
        'path resolves through a symlink pointing outside the target repo',
      );
    }
  } catch (error) {
    // ENOENT is expected for a new file. Anything else is a real problem.
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  if (touchesProtectedDir(normalised)) {
    throw new PathEscapeError(relativePath, 'path is inside a protected directory');
  }

  return resolved;
}

/** True when any segment of the path is a directory we protect. */
function touchesProtectedDir(relativePath: string): boolean {
  return relativePath
    .replace(/\\/g, '/')
    .split('/')
    .some((segment) => PROTECTED_DIRS.has(segment));
}

async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(full)));
    else out.push(path.relative(targetRoot(), full).split(path.sep).join('/'));
  }

  return out;
}

/** All source files of the target, as forward-slashed relative paths. */
export async function listSourceFiles(extensions: string[] = ['.js']): Promise<string[]> {
  const all = await walk(targetRoot());
  return all.filter((file) => extensions.some((ext) => file.endsWith(ext))).sort();
}

export async function readSourceFile(relativePath: string): Promise<string> {
  return fs.readFile(await resolveInsideTarget(relativePath), 'utf8');
}

/**
 * Overwrite a source file, returning what changed.
 *
 * The previous content is returned rather than discarded: the verify phase needs
 * it to put the file back, and a caller can diff the two.
 */
export async function overwriteSourceFile(
  relativePath: string,
  content: string,
): Promise<{ relativePath: string; previous: string | null; bytesWritten: number; changed: boolean }> {
  const absolute = await resolveInsideTarget(relativePath);

  let previous: string | null = null;
  try {
    previous = await fs.readFile(absolute, 'utf8');
  } catch (error) {
    // Creating a file that did not exist is fine; failing to read one that does
    // is not, so only ENOENT is tolerated here.
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }

  await fs.mkdir(path.dirname(absolute), { recursive: true });
  await fs.writeFile(absolute, content, 'utf8');

  return {
    relativePath: relativePath.replace(/\\/g, '/'),
    previous,
    bytesWritten: Buffer.byteLength(content, 'utf8'),
    changed: previous !== content,
  };
}

/** A single prompt-friendly dump of the whole target source tree. */
export async function sourceDigest(files?: string[]): Promise<string> {
  const targets = files ?? (await listSourceFiles());
  const parts: string[] = [];

  for (const file of targets) {
    const content = await readSourceFile(file);
    parts.push(`===== FILE: ${file} =====\n${content}`);
  }

  return parts.join('\n\n');
}

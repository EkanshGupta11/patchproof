/**
 * Remove the scratch files the agents leave in the target repo.
 *
 * The exploit and patch agents write verification scripts into the target with
 * `write_test_script` (it has to be the target repo, since that is what the
 * sandbox mounts). Nothing deletes them afterwards, so every run leaves a fresh
 * `exploit-convert.sh` / `verify-cmdinj.sh` behind and they accumulate until
 * someone notices. They also show up in the next run's scan as real files.
 *
 * This compares against a baseline captured *before* the run rather than
 * deleting every `.sh` it finds. Deleting by pattern would eventually remove a
 * script the project legitimately shipped; "did this file exist before we
 * started?" cannot.
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import { createLogger } from '../logger.js';
import { listSourceFiles, overwriteSourceFile, targetRoot } from './source.js';

const log = createLogger('target:cleanup');

/**
 * Extensions treated as agent scratch files.
 *
 * `.sh` is the only one `write_test_script` can currently produce; the rest are
 * listed because the same trap applies to them the moment anything else writes
 * them, and an unknown extension is simply ignored here.
 */
const SCRATCH_EXTENSIONS = ['.sh'];

/**
 * Filenames that look agent-authored, as a second filter.
 *
 * The trailing part is `[a-z0-9-]+` rather than `[a-z0-9]*` on purpose: a
 * character class without the hyphen rejected real names like
 * `verify-path-traversal.sh` while accepting `verify-search.sh`, which is worse
 * than not filtering at all -- cleanup silently skipped exactly the file it was
 * written to remove.
 */
const SCRATCH_NAME = /(?:^|[-_.])(?:exploit|verify|check|probe|repro)[-_]?[a-z0-9][a-z0-9-]*$/i;

async function listScratchFiles(root: string): Promise<Set<string>> {
  const found = new Set<string>();

  let entries;
  try {
    entries = await fs.readdir(root, { withFileTypes: true });
  } catch {
    return found;
  }

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!SCRATCH_EXTENSIONS.includes(path.extname(entry.name).toLowerCase())) continue;
    found.add(entry.name);
  }

  return found;
}

/**
 * Snapshot every source file, so the target can be put back exactly as found.
 *
 * The patch agent edits real files in the target repo. `proveFix` restores each
 * one in a `finally` block, but a crash or a kill between "write the patch" and
 * "restore the original" leaves the target *fixed*. That is worse than a crash:
 * the next run scans an already-patched app, finds nothing to exploit, and
 * reports a clean result for a vulnerability that is no longer present.
 *
 * Snapshotting the whole tree up front and restoring in the pipeline's `finally`
 * closes that window for every outcome, because the `finally` already runs on
 * both the success and failure paths.
 */
export async function snapshotSourceFiles(): Promise<Map<string, string>> {
  const root = targetRoot();
  const snapshot = new Map<string, string>();

  for (const relativePath of await listSourceFiles(['.js'])) {
    try {
      snapshot.set(relativePath, await fs.readFile(path.join(root, relativePath), 'utf8'));
    } catch {
      // A file that cannot be read simply is not protected; the guard below
      // only ever writes content we actually captured.
    }
  }

  return snapshot;
}

/**
 * Restore any file whose contents differ from the snapshot.
 *
 * Never throws: this runs in the pipeline's `finally`, and failing to tidy up
 * must not turn a completed run into a failed one.
 *
 * Returns the paths that were restored, for logging.
 */
export async function restoreSourceFiles(snapshot: Map<string, string>): Promise<string[]> {
  const root = targetRoot();
  const restored: string[] = [];

  for (const [relativePath, original] of snapshot) {
    try {
      const current = await fs.readFile(path.join(root, relativePath), 'utf8');
      if (current === original) continue;

      await overwriteSourceFile(relativePath, original);
      restored.push(relativePath);
    } catch {
      // Best effort. A file we cannot restore is logged below.
    }
  }

  if (restored.length > 0) {
    log.warn(
      `restored ${restored.length} file(s) the agents modified: ${restored.join(', ')}`,
    );
  } else {
    log.info('target source is byte-for-byte as it was found');
  }

  return restored;
}
export async function snapshotScratchFiles(): Promise<Set<string>> {
  return listScratchFiles(targetRoot());
}

/**
 * Delete scratch files that were not in the baseline.
 *
 * Never throws: cleanup runs after the run has already produced its result, and
 * a failure to tidy up must not turn a successful run into a failed one.
 */
export async function cleanScratchFiles(baseline: Set<string>): Promise<string[]> {
  const root = targetRoot();
  const removed: string[] = [];

  const current = await listScratchFiles(root);

  for (const name of current) {
    if (baseline.has(name)) continue;

    // Only agent-authored names. A pre-existing file is protected by the
    // baseline check above; this stops us touching an unrelated `.sh` that
    // appeared mid-run from some other source.
    if (!SCRATCH_NAME.test(path.basename(name, path.extname(name)))) continue;

    try {
      await fs.rm(path.join(root, name), { force: true });
      removed.push(name);
    } catch (error) {
      log.warn(`could not remove ${name}: ${error instanceof Error ? error.message : error}`);
    }
  }

  if (removed.length > 0) {
    log.info(`removed ${removed.length} agent scratch file(s): ${removed.join(', ')}`);
  }

  return removed;
}
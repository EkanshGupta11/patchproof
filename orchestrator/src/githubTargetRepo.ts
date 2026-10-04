/**
 * Which repository "Approve for shipping" opens pull requests against.
 *
 * Split out of `config.ts` on purpose: that module is a frozen `as const` object
 * describing the environment, while this is session state the dashboard changes
 * at runtime. Keeping mutable state out of the config object means the rest of
 * the config stays honestly immutable.
 *
 * The .env value stays the default. The override is deliberately in memory only:
 * on restart the orchestrator falls back to .env, so a run cannot silently push
 * to a repo someone typed into a browser tab during a previous session.
 */
import { config } from './config.js';

/** Set from the dashboard; undefined until someone sets one. */
let override: string | undefined;

/**
 * The repo a pull request would use right now: the dashboard override if there is
 * one, otherwise GITHUB_DEFAULT_REPO.
 *
 * Blank values collapse to undefined so an empty GITHUB_DEFAULT_REPO in .env
 * behaves the same as an unset one. Otherwise "" is a real value and the dashboard
 * renders an empty "PRs go to " instead of "no repo configured".
 */
export function currentTargetRepo(): string | undefined {
  const value = override ?? config.github.defaultRepo;
  return value && value.trim().length > 0 ? value : undefined;
}

/** Record a new target repo. Already normalised by `normaliseRepoInput`. */
export function setTargetRepo(slug: string): void {
  override = slug;
}

/** Drop the override and fall back to .env. */
export function clearTargetRepo(): void {
  override = undefined;
}

/** True when the current value differs from the .env default. */
export function isTargetRepoOverridden(): boolean {
  return Boolean(override && override !== config.github.defaultRepo);
}
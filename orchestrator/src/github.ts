/**
 * GitHub client for the orchestrator.
 *
 * Used to read target repositories (issue the patch can be turned into) and, in
 * future, to post findings or open PRs for verified fixes.
 *
 * The token is optional: with none, the client still works but is rate-limited
 * to 60 requests/hour and cannot access private repositories.
 */
import { Octokit } from '@octokit/rest';
import { config } from './config.js';

export function createGitHubClient(): Octokit {
  return new Octokit({
    userAgent: 'patchproof-orchestrator',
    ...(config.github.token ? { auth: config.github.token } : {}),
  });
}

/** True when a token is configured, i.e. we are not stuck on anonymous limits. */
export function hasGitHubToken(): boolean {
  return Boolean(config.github.token);
}

/** Repo coordinates, normalised from "owner/name". */
export interface RepoRef {
  owner: string;
  repo: string;
}

export function parseRepoRef(slug: string): RepoRef {
  const [owner, repo] = slug.split('/');
  if (!owner || !repo) {
    throw new Error(`Expected a repository slug like "owner/name", got "${slug}"`);
  }
  return { owner, repo };
}

/**
 * GitHub owner and name characters.
 *
 * Deliberately narrower than what GitHub actually permits: this is a sanity
 * check to catch a pasted browser URL or a typo, not a reimplementation of
 * GitHub's naming rules.
 */
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Normalise whatever the user pasted into a bare "owner/name" slug.
 *
 * Accepts, because all of these are things people actually paste:
 *   acme/shop
 *   https://github.com/acme/shop
 *   github.com/acme/shop
 *   https://github.com/acme/shop.git/
 *   git@github.com:acme/shop.git
 *
 * Returns the canonical slug, or throws with a message worth showing in the UI.
 * The URL forms are stripped rather than rejected so that pasting the browser
 * address bar -- the obvious thing to do -- just works.
 */
export function normaliseRepoInput(input: string): string {
  const trimmed = (input ?? '').trim();
  if (!trimmed) throw new Error('Enter a repository as "owner/name" or a GitHub URL');

  let text = trimmed;

  // git@github.com:acme/shop.git
  text = text.replace(/^git@([^:]+):/, 'https://$1/');
  // Scheme + host, with or without "www.". The host is optional so that a bare
  // "github.com/acme/shop" -- which is what people paste after trimming the
  // scheme in some UIs -- is recognised too.
  text = text.replace(/^(?:https?:\/\/)?(?:www\.)?github\.com\//i, '');
  // A non-GitHub URL (a self-hosted instance, say) is not something we can map
  // onto owner/name, so say so rather than mangling it.
  const otherHost = /^(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})\//i.exec(text);
  if (otherHost) {
    throw new Error(
      `"${trimmed}" is not a github.com URL. Use "owner/name", or the GitHub URL of the repository.`,
    );
  }
  // Pasted sub-page URLs: /tree/main, /pull/42, /blob/main/src, ...
  text = text.replace(/\/(?:tree|blob|pull|issues|commits|releases|actions|wiki)\/.*$/i, '');
  // Query strings and fragments.
  text = text.split(/[?#]/)[0] ?? '';
  text = text.replace(/^\/+/, '');
  text = text.replace(/\.git$/i, '').replace(/\/+$/, '');

  const parts = text.split('/').filter(Boolean);
  if (parts.length !== 2) {
    throw new Error(
      `Expected "owner/name" or a GitHub URL, got "${trimmed}"` +
        (parts.length > 2 ? ' (use just owner/name, without the extra path)' : ''),
    );
  }

  const [owner, repo] = parts as [string, string];

  if (!OWNER.test(owner)) throw new Error(`"${owner}" is not a valid GitHub owner or organisation`);
  if (!REPO.test(repo)) throw new Error(`"${repo}" is not a valid repository name`);

  return `${owner}/${repo}`;
}

/**
 * Fetch a file from a repository at a given ref.
 * Returns null when the file or ref does not exist.
 */
export async function fetchRepoFile(
  client: Octokit,
  { owner, repo }: RepoRef,
  path: string,
  ref?: string,
): Promise<string | null> {
  try {
    const response = await client.repos.getContent({ owner, repo, path, ...(ref ? { ref } : {}) });

    // getContent returns a directory or symlink as an array; only a file has content.
    if (Array.isArray(response.data) || response.data.type !== 'file' || !('content' in response.data)) {
      return null;
    }

    return Buffer.from(response.data.content, 'base64').toString('utf8');
  } catch (error) {
    const status = (error as { status?: number }).status;
    if (status === 404) return null;
    throw error;
  }
}
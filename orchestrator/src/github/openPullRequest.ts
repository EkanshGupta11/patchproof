/**
 * Opening the pull request.
 *
 * All GitHub access goes through a tiny structural interface rather than
 * `Octokit` directly, so the call sequence can be exercised with a stub instead
 * of a live token. Only the four endpoints actually used are declared.
 */
import { createGitHubClient, hasGitHubToken, parseRepoRef, type RepoRef } from '../github.js';
import { currentTargetRepo } from '../githubTargetRepo.js';
import { branchNameFor, commitMessageFor, prTitleFor, renderPrBody, type PrEvidence } from './prReport.js';
import { config } from '../config.js';
import { createLogger } from '../logger.js';
import type { PullRequestRef } from '../types.js';

const log = createLogger('github:pr');

/** The slice of the Octokit surface this module uses. */
export interface GitHubApi {
  repos: {
    get(params: { owner: string; repo: string }): Promise<{ data: { default_branch: string } }>;
    getContent(params: {
      owner: string;
      repo: string;
      path: string;
    }): Promise<{ data: { sha?: string; content?: string } | unknown[] }>;
    createOrUpdateFileContents(params: {
      owner: string;
      repo: string;
      path: string;
      message: string;
      content: string;
      branch: string;
      sha?: string;
      create?: boolean;
    }): Promise<unknown>;
  };
  git: {
    getRef(params: { owner: string; repo: string; ref: string }): Promise<{ data: { object: { sha: string } } }>;
    createRef(params: { owner: string; repo: string; ref: string; sha: string }): Promise<unknown>;
    deleteRef(params: { owner: string; repo: string; ref: string }): Promise<unknown>;
  };
  pulls: {
    create(params: {
      owner: string;
      repo: string;
      title: string;
      head: string;
      base: string;
      body: string;
    }): Promise<{ data: { number: number; html_url: string } }>;
  };
}

export interface OpenPullRequestOptions {
  /**
   * "owner/name". Defaults to the dashboard override, then to GITHUB_DEFAULT_REPO.
   */
  repo?: string;
  /** Base branch. Defaults to the repository's default branch. */
  baseBranch?: string;
  /** Injected client; defaults to a real Octokit. */
  client?: GitHubApi;
}

export interface PullRequestResult {
  ok: boolean;
  reason?: string;
  pullRequest?: PullRequestRef;
}

/** True when there is enough configuration to attempt a pull request. */
export function canOpenPullRequest(repo?: string): boolean {
  return Boolean(repo ?? currentTargetRepo()) && hasGitHubToken();
}

/**
 * Open a pull request carrying the patched file and the verification report.
 *
 * Sequence: resolve the base branch -> create a branch -> commit the patched
 * file -> open the PR. A branch that already exists is deleted and recreated, so
 * re-running after a failure does not wedge.
 */
export async function openPullRequest(
  evidence: PrEvidence,
  options: OpenPullRequestOptions = {},
): Promise<PullRequestResult> {
  const slug = options.repo ?? currentTargetRepo();
  if (!slug) {
    return {
      ok: false,
      reason: 'no repository configured (set one in the dashboard or GITHUB_DEFAULT_REPO)',
    };
  }

  // A token is only needed when we build our own client. An injected client
  // carries its own credentials (or is a test double), so demanding a token here
  // would block both testing and any alternative auth path.
  if (!options.client && !hasGitHubToken()) {
    return { ok: false, reason: 'no GITHUB_TOKEN configured' };
  }

  let ref: RepoRef;
  try {
    ref = parseRepoRef(slug);
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }

  const { owner, repo } = ref;
  const client = (options.client ?? createGitHubClient()) as unknown as GitHubApi;
  const branch = branchNameFor(evidence);

  try {
    // 1. Base branch and its head commit.
    const base = options.baseBranch ?? (await client.repos.get({ owner, repo })).data.default_branch;
    const baseSha = (await client.git.getRef({ owner, repo, ref: `heads/${base}` })).data.object.sha;

    // 2. Branch off the base. Delete first so a retry is not blocked by 422.
    try {
      await client.git.createRef({ owner, repo, ref: `refs/heads/${branch}`, sha: baseSha });
    } catch (error) {
      if ((error as { status?: number }).status !== 422) throw error;
      log.info(`branch ${branch} already exists; recreating it`);
      await client.git.deleteRef({ owner, repo, ref: `heads/${branch}` });
      await client.git.createRef({ owner, repo, ref: `refs/heads/${branch}`, sha: baseSha });
    }

    // 3. Commit the patched file. The blob must be base64 for the contents API.
    let sha: string | undefined;
    try {
      const existing = await client.repos.getContent({ owner, repo, path: evidence.file });
      if (!Array.isArray(existing.data) && typeof existing.data.sha === 'string') {
        sha = existing.data.sha;
      }
    } catch (error) {
      // 404 means the file is new, which createOrUpdateFileContents handles.
      if ((error as { status?: number }).status !== 404) throw error;
    }

    await client.repos.createOrUpdateFileContents({
      owner,
      repo,
      path: evidence.file,
      message: commitMessageFor(evidence),
      content: Buffer.from(evidence.patchedContent, 'utf8').toString('base64'),
      branch,
      ...(sha ? { sha } : {}),
      ...(sha ? {} : { create: true }),
    });

    // 4. Open the pull request.
    const pr = await client.pulls.create({
      owner,
      repo,
      title: prTitleFor(evidence),
      head: branch,
      base,
      body: renderPrBody(evidence),
    });

    const pullRequest: PullRequestRef = {
      owner,
      repo,
      number: pr.data.number,
      branch,
      url: pr.data.html_url,
      openedAt: new Date().toISOString(),
    };

    log.info(`opened PR #${pr.data.number} for ${evidence.findingId}: ${pr.data.html_url}`);
    return { ok: true, pullRequest };
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    log.error(`failed to open PR for ${evidence.findingId}`, error);
    return { ok: false, reason };
  }
}
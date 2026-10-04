import { useEffect, useState } from 'react';
import * as api from '../api';
import type { GithubConfig } from '../api';

interface RepoFieldProps {
  /** Current settings from the server; null until loaded. */
  config: GithubConfig | null;
  /** Called with the server's response so the parent's copy stays truthful. */
  onChange: (next: GithubConfig) => void;
}

/**
 * Target repository for "Approve for shipping" pull requests.
 *
 * Accepts "owner/name" or a pasted GitHub URL -- the server normalises both, so
 * the browser does not have to duplicate those rules and drift from them.
 *
 * Deliberately not a form that saves on every keystroke: the value is only
 * committed on Save or Enter, so a half-typed slug never becomes the PR target.
 */
export function RepoField({ config, onChange }: RepoFieldProps) {
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  // Seed the box from the server, but only while the user has not started
  // editing: overwriting the field mid-typing would fight the user.
  const current = config?.repo ?? '';
  useEffect(() => {
    if (current && draft === '') setDraft(current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [current]);

  const save = async (value: string): Promise<void> => {
    const trimmed = value.trim();

    // Empty means "go back to the .env default", which is what an empty box
    // intuitively means rather than "no repository at all".
    if (trimmed === '') {
      try {
        setSaving(true);
        setProblem(null);
        const next = await api.setTargetRepo(null);
        onChange(next);
        setDraft(next.repo ?? '');
        setSaved(true);
      } catch (err) {
        setProblem(err instanceof Error ? err.message : String(err));
      } finally {
        setSaving(false);
      }
      return;
    }

    try {
      setSaving(true);
      setProblem(null);
      // Adopt the server's normalised value, so what is shown is what is stored.
      const next = await api.setTargetRepo(trimmed);
      onChange(next);
      setDraft(next.repo ?? trimmed);
      setSaved(true);
    } catch (err) {
      // Leave the text alone so it can be corrected rather than discarded.
      setProblem(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  const dirty = draft.trim() !== current;
  const showDefault = Boolean(config?.defaultRepo) && config?.defaultRepo !== current;

  return (
    <div className="bar repo-bar">
      <label className="field repo-field">
        GitHub repo for PRs
        <input
          type="text"
          placeholder="owner/name or https://github.com/owner/name"
          value={draft}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => {
            setDraft(e.target.value);
            setSaved(false);
            setProblem(null);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') void save(draft);
          }}
          disabled={saving}
        />
      </label>

      <button
        type="button"
        onClick={() => void save(draft)}
        disabled={saving || !dirty}
        title={dirty ? 'Save the repository for pull requests' : 'Already saved'}
      >
        {saving ? 'Saving…' : 'Save'}
      </button>

      {saved && !dirty ? <span className="meta ok">saved</span> : null}
      {problem ? <span className="meta bad">{problem}</span> : null}

      {/* What it will actually use, so this is never a guess. */}
      <span className="meta">
        {current ? (
          <>
            PRs go to <code>{current}</code>
            {config?.overridden ? <span className="tag">override</span> : null}
          </>
        ) : (
          'no repo configured'
        )}
      </span>

      {showDefault ? (
        <span className="meta">
          default from .env: <code>{config?.defaultRepo}</code>
        </span>
      ) : null}

      {config && !config.tokenConfigured ? (
        <span className="meta warn">no GITHUB_TOKEN — approval will not open a PR</span>
      ) : null}
    </div>
  );
}
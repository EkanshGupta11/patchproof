import { useCallback, useEffect, useState } from 'react';
import * as api from './api';
import type { GithubConfig, RunStatus } from './api';
import { useRunStream } from './hooks/useRunStream';
import { FindingRow } from './components/FindingRow';
import { EventLog } from './components/EventLog';
import { RepoField } from './components/RepoField';

export default function App() {
  const [runId, setRunId] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [approvingId, setApprovingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [maxFindings, setMaxFindings] = useState(1);
  const [online, setOnline] = useState<boolean | null>(null);
  const [github, setGithub] = useState<GithubConfig | null>(null);

  const { findings, run, events, connected, finished } = useRunStream(runId);

  useEffect(() => {
    api
      .getHealth()
      .then(() => setOnline(true))
      .catch(() => setOnline(false));
  }, []);

  // Load the current PR target once, so the field starts showing what is really
  // configured rather than an empty box.
  useEffect(() => {
    api
      .getConfig()
      .then((config) => setGithub(config.github))
      .catch(() => setGithub(null));
  }, []);

  const startRun = useCallback(async () => {
    setStarting(true);
    setError(null);
    try {
      // A fresh run starts from a clean slate.
      const { runId: id } = await api.startRun({ maxFindings });
      setRunId(id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setStarting(false);
    }
  }, [maxFindings]);

  const approve = useCallback(
    async (findingId: string) => {
      if (!runId) return;
      setApprovingId(findingId);
      setError(null);
      try {
        const result = await api.approveFinding(runId, findingId);
        if (!result.ok) setError(result.reason ?? 'approval refused');
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        setApprovingId(null);
      }
    },
    [runId],
  );

  const counts = {
    candidates: findings.length,
    confirmed: findings.filter((f) => f.exploit === 'confirmed').length,
    verified: findings.filter((f) => f.verify === 'verified').length,
    approved: findings.filter((f) => f.approved).length,
  };

  const statusLabel: Record<RunStatus, string> = {
    running: 'Running',
    completed: 'Completed',
    failed: 'Failed',
  };

  return (
    <div className="app">
      <header>
        <h1>
          PatchProof <span className="tagline">prove it, don&rsquo;t guess it</span>
        </h1>
        <div className="status-line">
          <span className={`dot ${online ? 'dot-ok' : 'dot-bad'}`} />
          <span className="meta">
            orchestrator {online === null ? 'checking…' : online ? 'online' : 'unreachable'}
          </span>
          {runId ? (
            <>
              <span className="meta">run {runId.slice(0, 8)}</span>
              <span className={`meta ${connected ? 'live' : ''}`}>{connected ? '● streaming' : '○ not streaming'}</span>
            </>
          ) : null}
        </div>
      </header>

      <div className="bar">
        <button type="button" onClick={startRun} disabled={starting || !online}>
          {starting ? 'Starting…' : 'Start run'}
        </button>
        <label className="field">
          findings
          <input
            type="number"
            min={1}
            max={20}
            value={maxFindings}
            onChange={(e) => setMaxFindings(Number(e.target.value) || 1)}
          />
        </label>
        {runId ? (
          <span className={`pill pill-${run.status}`}>
            {statusLabel[run.status]}
            {run.status === 'running' ? '…' : ''}
          </span>
        ) : null}
      </div>

      <RepoField config={github} onChange={setGithub} />

      {error ? <p className="error">{error}</p> : null}
      {run.error ? <p className="error">{run.error}</p> : null}

      {runId ? (
        <div className="counters">
          <div className="counter">
            <span className="counter-value" key={counts.candidates}>
              {counts.candidates}
            </span>
            <span className="counter-label">candidates</span>
          </div>
          <div className="counter counter-bad">
            <span className="counter-value" key={counts.confirmed}>
              {counts.confirmed}
            </span>
            <span className="counter-label">confirmed</span>
          </div>
          <div className="counter counter-good">
            {/* Keyed by the value so a change remounts the element and restarts
                its one-shot glow; an unchanged value never pulses. Presentation
                only -- it does not affect what is counted or when. */}
            <span className="counter-value" key={counts.verified}>
              {counts.verified}
            </span>
            <span className="counter-label">verified</span>
          </div>
          <div className="counter counter-good">
            <span className="counter-value" key={counts.approved}>
              {counts.approved}
            </span>
            <span className="counter-label">approved</span>
          </div>
        </div>
      ) : null}

      <div className="panel">
        <h2>Pipeline</h2>
        {!runId ? (
          <div className="meta">Start a run to watch findings move through scan → exploit → patch → verify.</div>
        ) : findings.length === 0 ? (
          <div className="meta">{finished ? 'The run finished with no findings.' : 'Scanning…'}</div>
        ) : (
          findings.map((finding) => (
            <FindingRow
              key={finding.id}
              finding={finding}
              onApprove={approve}
              approving={approvingId === finding.id}
              disabled={approvingId !== null}
            />
          ))
        )}
      </div>

      <div className="panel">
        <h2>Event stream</h2>
        <EventLog events={events} />
      </div>
    </div>
  );
}
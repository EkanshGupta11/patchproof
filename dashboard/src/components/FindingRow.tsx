import type { FindingProgress } from '../hooks/useRunStream';

interface PhaseCellProps {
  label: string;
  state: string;
  /** Extra text under the state, e.g. the test summary. */
  detail?: string;
}

/**
 * One phase in the pipeline.
 *
 * Colour carries the meaning, so it is also spelled out in the state text rather
 * than left to colour alone -- colour-blind users and anyone reading a
 * screenshot get the same information.
 */
export function PhaseCell({ label, state, detail }: PhaseCellProps) {
  return (
    <div className={`phase-cell phase-${state}`}>
      <span className="phase-label">{label}</span>
      <span className="phase-state">{state}</span>
      {detail ? <span className="phase-detail">{detail}</span> : null}
    </div>
  );
}

interface FindingRowProps {
  finding: FindingProgress;
  onApprove: (id: string) => void;
  approving: boolean;
  disabled: boolean;
}

/**
 * One finding's row: what it is, where it is, and how far it has got.
 *
 * The Approve button appears as soon as the fix is verified. The server refuses
 * anything it has not marked `verified`, so this is a convenience rather than
 * the actual gate.
 */
export function FindingRow({ finding, onApprove, approving, disabled }: FindingRowProps) {
  const verified = finding.verify === 'verified';
  const showApprove = verified && !finding.approved;

  return (
    <div className={`finding-row ${verified ? 'finding-verified' : finding.exploit === 'confirmed' ? 'finding-confirmed' : ''}`}>
      <div className="finding-head">
        <span className={`sev sev-${finding.severity}`}>{finding.severity}</span>
        <span className="finding-class">{finding.vulnerabilityClass}</span>
        <span className="finding-id">{finding.id}</span>
        <span className="finding-location">
          {finding.file}
          {finding.line ? `:${finding.line}` : ''}
        </span>
        {finding.ruleId ? <span className="finding-rule">{finding.ruleId}</span> : null}
      </div>

      <div className="finding-phases">
        <PhaseCell label="scan" state="done" detail="found" />
        <PhaseCell label="exploit" state={finding.exploit} />
        <PhaseCell label="patch" state={finding.patch} />
        <PhaseCell label="verify" state={finding.verify} detail={finding.testSummary} />
      </div>

      {finding.summary ? <div className="finding-summary">{finding.summary}</div> : null}

      <div className="finding-actions">
        {finding.approved ? (
          <span className="approved-flag">approved{finding.approvedAt ? ` at ${new Date(finding.approvedAt).toLocaleTimeString()}` : ''}</span>
        ) : showApprove ? (
          <button type="button" className="approve" onClick={() => onApprove(finding.id)} disabled={approving || disabled}>
            {approving ? 'approving…' : 'Approve for shipping'}
          </button>
        ) : (
          <span className="approve-hint">
            {verified ? '' : 'Approve appears once the fix is verified'}
          </span>
        )}
      </div>
    </div>
  );
}
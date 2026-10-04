import type { PipelineEvent } from '../api';

interface EventLogProps {
  events: PipelineEvent[];
}

/** Raw event stream, newest first. Useful when a run does something surprising. */
export function EventLog({ events }: EventLogProps) {
  const ordered = [...events].reverse();

  return (
    <div className="events">
      {ordered.length === 0 ? (
        <div className="meta">No events yet.</div>
      ) : (
        ordered.map((event, index) => (
          <div className="event" key={`${event.at}-${index}`}>
            <span className={`event-phase phase-${event.phase}`}>{event.type}</span>
            <span className="event-time">{new Date(event.at).toLocaleTimeString()}</span>
            <span className="event-message">{event.message}</span>
          </div>
        ))
      )}
    </div>
  );
}
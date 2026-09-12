// Status and severity are told apart by text and hairline weight, not by a
// rainbow of filled badges. Orange is reserved for what needs attention.

export function JobStatus({ status }: { status: string }) {
  if (status === "running") {
    return (
      <span className="tag border-ink text-ink">
        <span className="h-1.5 w-1.5 animate-pulse bg-brand" aria-hidden />
        running
      </span>
    );
  }
  if (status === "failed") return <span className="tag border-brand-dim text-brand-dim">failed</span>;
  if (status === "done") return <span className="tag border-ink text-ink">complete</span>;
  return <span className="tag">{status}</span>;
}

export function Severity({ level }: { level: string | null }) {
  const s = (level || "INFO").toUpperCase();
  if (s === "CRITICAL") return <span className="tag border-brand bg-brand/5 text-brand">critical</span>;
  if (s === "HIGH") return <span className="tag border-brand-dim text-brand-dim">high</span>;
  if (s === "MEDIUM") return <span className="tag border-ink text-ink">medium</span>;
  return <span className="tag">{s.toLowerCase()}</span>;
}

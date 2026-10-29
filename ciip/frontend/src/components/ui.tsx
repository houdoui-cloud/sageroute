import { useCallback, useEffect, useState, type ReactNode } from "react";
import { CATEGORY, SEVERITY, STATUS, label } from "../lib/format";

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const run = useCallback(fn, deps);
  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await run());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [run]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { data, error, loading, reload, setData };
}

export function SeverityBadge({ value }: { value: string }) {
  return <span className={`badge sev-${value}`}>{label(SEVERITY, value)}</span>;
}

export function StatusBadge({ value }: { value: string }) {
  return <span className={`badge st-${value}`}>{label(STATUS, value)}</span>;
}

export function TlpBadge({ value }: { value: string }) {
  return <span className={`badge tlp tlp-${value.replace("+", "-")}`}>TLP:{value.toUpperCase()}</span>;
}

export function CategoryTag({ value }: { value: string }) {
  return <span className="tag">{label(CATEGORY, value)}</span>;
}

export function Card({ title, actions, children, className = "" }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Kpi({ label: text, value, hint, tone }: { label: string; value: ReactNode; hint?: string; tone?: string }) {
  return (
    <div className={`kpi ${tone ? `kpi-${tone}` : ""}`}>
      <div className="kpi-label">{text}</div>
      <div className="kpi-value">{value}</div>
      {hint && <div className="kpi-hint">{hint}</div>}
    </div>
  );
}

export function Loading() {
  return <div className="muted pad">Chargement…</div>;
}

export function ErrorBox({ message }: { message: string | null }) {
  if (!message) return null;
  return <div className="alert alert-error" role="alert">{message}</div>;
}

export function Notice({ children, tone = "info" }: { children: ReactNode; tone?: "info" | "warn" | "ok" }) {
  return <div className={`alert alert-${tone}`}>{children}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <header className="card-head">
          <h2>{title}</h2>
          <button className="btn-ghost" onClick={onClose} aria-label="Fermer">✕</button>
        </header>
        {children}
      </div>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: {
  tabs: { id: T; label: ReactNode }[]; value: T; onChange: (id: T) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={value === t.id ? "tab active" : "tab"}
          onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Pager({ page, size, total, onPage }: { page: number; size: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / size));
  return (
    <div className="pager">
      <span className="muted">{total} résultat{total > 1 ? "s" : ""}</span>
      <button className="btn-ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹ Précédent</button>
      <span>{page} / {pages}</span>
      <button className="btn-ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>Suivant ›</button>
    </div>
  );
}

/** Runs an async action, exposing busy/error state for a form or button. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, error, run, setError };
}

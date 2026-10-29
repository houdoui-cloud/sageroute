import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Card, CategoryTag, Empty, ErrorBox, Loading, Modal, Pager, SeverityBadge, StatusBadge, useAction, useAsync } from "../components/ui";
import { api, download, qs } from "../lib/api";
import { useAuth } from "../lib/auth";
import { CATEGORY, SEVERITY, STATUS, fmtDate, relative } from "../lib/format";
import type { Incident, IncidentDetail, Page, UserBrief } from "../types";

function CreateIncident({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const assignees = useAsync(() => api<UserBrief[]>("/admin/assignees"), []);
  const [f, setF] = useState({ title: "", description: "", category: "other", severity: "medium", assets: "", assignee_id: "" });
  const { busy, error, run } = useAction();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const inc = await run(() =>
      api<IncidentDetail>("/incidents", {
        body: {
          title: f.title,
          description: f.description,
          category: f.category,
          severity: f.severity,
          affected_assets: f.assets.split(",").map((s) => s.trim()).filter(Boolean),
          assignee_id: f.assignee_id || null,
        },
      }),
    );
    if (inc) navigate(`/incidents/${inc.id}`);
  };

  return (
    <Modal title="Nouvel incident" onClose={onClose}>
      <form className="form" onSubmit={submit}>
        <label>Titre<input required minLength={3} value={f.title} onChange={set("title")} /></label>
        <label>Description<textarea rows={4} value={f.description} onChange={set("description")} /></label>
        <div className="grid3">
          <label>Catégorie
            <select value={f.category} onChange={set("category")}>
              {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <label>Sévérité
            <select value={f.severity} onChange={set("severity")}>
              {Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <label>Assigné à
            <select value={f.assignee_id} onChange={set("assignee_id")}>
              <option value="">— non assigné —</option>
              {assignees.data?.map((u) => <option key={u.id} value={u.id}>{u.full_name}</option>)}
            </select>
          </label>
        </div>
        <label>Actifs touchés (séparés par des virgules)<input value={f.assets} onChange={set("assets")} /></label>
        <ErrorBox message={error} />
        <button className="btn" disabled={busy}>Créer le ticket</button>
      </form>
    </Modal>
  );
}

export default function Incidents() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const [creating, setCreating] = useState(false);
  const filters = {
    q: params.get("q") ?? "",
    status: params.get("status") ?? "",
    severity: params.get("severity") ?? "",
    category: params.get("category") ?? "",
    open_only: params.get("open_only") === "1",
    page: Number(params.get("page") ?? 1),
  };
  const update = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "page") next.delete("page");
    setParams(next);
  };
  const { data, error, loading } = useAsync(
    () => api<Page<Incident>>(`/incidents${qs({ ...filters, open_only: filters.open_only || undefined, size: 25 })}`),
    [params.toString()],
  );

  return (
    <div className="page">
      <div className="page-head">
        <h1>Gestion des incidents</h1>
        <div className="row">
          {can("reports:read") && <button className="btn-ghost" onClick={() => void download("/incidents/export.csv", "incidents.csv")}>Export CSV</button>}
          {can("incident:write") && <button className="btn" onClick={() => setCreating(true)}>+ Nouvel incident</button>}
        </div>
      </div>
      <Card>
        <div className="filters">
          <input placeholder="Rechercher (référence, titre, description)" defaultValue={filters.q}
            onKeyDown={(e) => e.key === "Enter" && update("q", (e.target as HTMLInputElement).value)} />
          <select value={filters.status} onChange={(e) => update("status", e.target.value)}>
            <option value="">Tous statuts</option>
            {Object.entries(STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select value={filters.severity} onChange={(e) => update("severity", e.target.value)}>
            <option value="">Toutes sévérités</option>
            {Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select value={filters.category} onChange={(e) => update("category", e.target.value)}>
            <option value="">Toutes catégories</option>
            {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <label className="check">
            <input type="checkbox" checked={filters.open_only} onChange={(e) => update("open_only", e.target.checked ? "1" : "")} />
            Ouverts uniquement
          </label>
        </div>
        <ErrorBox message={error} />
        {loading && !data ? <Loading /> : data && data.items.length === 0 ? <Empty>Aucun incident ne correspond.</Empty> : (
          <table className="table">
            <thead>
              <tr><th>Référence</th><th>Titre</th><th>Catégorie</th><th>Sévérité</th><th>Statut</th><th>Escalade</th><th>Assigné</th><th>SLA résolution</th></tr>
            </thead>
            <tbody>
              {data?.items.map((i) => (
                <tr key={i.id} className={i.sla_breached && !["closed", "resolved", "rejected"].includes(i.status) ? "row-breach" : ""}>
                  <td><Link to={`/incidents/${i.id}`} className="mono">{i.reference}</Link></td>
                  <td>{i.title}</td>
                  <td><CategoryTag value={i.category} /></td>
                  <td><SeverityBadge value={i.severity} /></td>
                  <td><StatusBadge value={i.status} /></td>
                  <td>{i.escalation_level === "external" ? "CERT" : i.escalation_level}</td>
                  <td>{i.assignee?.full_name ?? <span className="muted">—</span>}</td>
                  <td title={fmtDate(i.sla_resolve_due)}>
                    {i.resolved_at ? <span className="muted">résolu</span> : (
                      <span className={i.sla_breached ? "danger" : ""}>{relative(i.sla_resolve_due)}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {data && <Pager page={filters.page} size={25} total={data.total} onPage={(p) => update("page", String(p))} />}
      </Card>
      {creating && <CreateIncident onClose={() => setCreating(false)} />}
    </div>
  );
}

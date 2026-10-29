import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Card, CategoryTag, ErrorBox, Loading, Modal, Notice, SeverityBadge, StatusBadge, TlpBadge, useAction, useAsync } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { CATEGORY, CHANNEL, EVENT, NEXT_STATUSES, SEVERITY, STATUS, fmtDate, label, relative } from "../lib/format";
import type { IncidentDetail as Detail, Playbook, Suggestion, UserBrief } from "../types";
import { SuggestionCard } from "./Assistant";

const LEVELS = ["L1", "L2", "L3"];

function DecisionDialog({ incident, type, onClose, onDone }: {
  incident: Detail; type: "close_critical_incident" | "external_escalation"; onClose: () => void; onDone: () => void;
}) {
  const [justification, setJustification] = useState("");
  const { busy, error, run } = useAction();
  const submit = async () => {
    const r = await run(() => api("/decisions", { body: { type, target_id: incident.id, justification } }));
    if (r) {
      onDone();
      onClose();
    }
  };
  return (
    <Modal title={type === "external_escalation" ? "Demander une escalade au CERT national" : "Demander la clôture d'un incident critique"} onClose={onClose}>
      <Notice tone="warn">
        Décision sensible : elle ne sera exécutée qu'après approbation par un analyste habilité <strong>autre que vous</strong> (principe des quatre yeux).
      </Notice>
      <label className="form">
        Justification
        <textarea rows={4} value={justification} onChange={(e) => setJustification(e.target.value)} minLength={10} />
      </label>
      <ErrorBox message={error} />
      <button className="btn" disabled={busy || justification.length < 10} onClick={() => void submit()}>Soumettre pour approbation</button>
    </Modal>
  );
}

export default function IncidentDetail() {
  const { id } = useParams();
  const { can } = useAuth();
  const { data: inc, error, loading, reload, setData } = useAsync(() => api<Detail>(`/incidents/${id}`), [id]);
  const assignees = useAsync(() => api<UserBrief[]>("/admin/assignees"), []);
  const suggestions = useAsync(
    () => (can("ai:use") ? api<Suggestion[]>(`/ai/suggestions?incident_id=${id}`) : Promise.resolve([])), [id]);
  const playbook = useAsync(
    () => (inc?.playbook_id ? api<Playbook>(`/playbooks/${inc.playbook_id}`) : Promise.resolve(null)), [inc?.playbook_id]);
  const playbooks = useAsync(() => api<Playbook[]>("/playbooks"), []);
  const [comment, setComment] = useState("");
  const [statusComment, setStatusComment] = useState("");
  const [escalation, setEscalation] = useState({ to_level: "", reason: "" });
  const [ioc, setIoc] = useState("");
  const [dialog, setDialog] = useState<null | "close_critical_incident" | "external_escalation">(null);
  const action = useAction();
  const writable = can("incident:write");

  if (loading && !inc) return <Loading />;
  if (!inc) return <ErrorBox message={error} />;

  const mutate = async (path: string, body: unknown, method = "POST") => {
    const r = await action.run(() => api<Detail>(`/incidents/${inc.id}${path}`, { body, method }));
    if (r) setData(r);
    return r;
  };

  const setStatus = async (status: string) => {
    if (status === "closed" && inc.severity === "critical") {
      setDialog("close_critical_incident");
      return;
    }
    if (await mutate("/status", { status, comment: statusComment })) setStatusComment("");
  };

  const triage = async () => {
    const r = await action.run(() => api<Suggestion>("/ai/triage", { body: { incident_id: inc.id } }));
    if (r) void suggestions.reload();
  };

  const addIoc = async () => {
    const r = await action.run(() => api("/intel/iocs", { body: { value: ioc, incident_id: inc.id, source: inc.reference } }));
    if (r) {
      setIoc("");
      void reload();
    }
  };

  const playbookSteps = playbook.data?.steps ?? [];

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <Link to="/incidents" className="muted">‹ Incidents</Link>
          <h1><span className="mono">{inc.reference}</span> — {inc.title}</h1>
          <div className="row">
            <SeverityBadge value={inc.severity} /> <StatusBadge value={inc.status} /> <CategoryTag value={inc.category} />
            <span className="tag">Escalade : {inc.escalation_level === "external" ? "CERT national" : inc.escalation_level}</span>
            {inc.sla_breached && <span className="badge sev-critical">SLA dépassé</span>}
            {inc.pending_decisions > 0 && <span className="badge st-triaged">{inc.pending_decisions} décision(s) en attente</span>}
          </div>
        </div>
      </div>
      <ErrorBox message={action.error} />

      <div className="grid-detail">
        <div className="stack">
          <Card title="Description">
            <p className="prewrap">{inc.description || <span className="muted">—</span>}</p>
            <dl className="dl">
              <dt>Canal d'origine</dt><dd>{label(CHANNEL, inc.source_channel)}</dd>
              <dt>Actifs touchés</dt><dd>{inc.affected_assets.join(", ") || "—"}</dd>
              <dt>Déclaré le</dt><dd>{fmtDate(inc.created_at)}</dd>
              <dt>SLA prise en charge</dt><dd>{inc.acknowledged_at ? `pris en charge le ${fmtDate(inc.acknowledged_at)}` : relative(inc.sla_ack_due)}</dd>
              <dt>SLA résolution</dt><dd>{inc.resolved_at ? `résolu le ${fmtDate(inc.resolved_at)}` : `${relative(inc.sla_resolve_due)} (${fmtDate(inc.sla_resolve_due)})`}</dd>
            </dl>
          </Card>

          <Card title="Chronologie">
            <ol className="timeline">
              {inc.events.map((e) => (
                <li key={e.id} className={`ev ev-${e.kind}`}>
                  <div className="ev-head">
                    <strong>{label(EVENT, e.kind)}</strong>
                    {"from" in e.data && "to" in e.data && (
                      <span className="muted"> {String(e.data.from)} → {String(e.data.to)}</span>
                    )}
                    <span className="muted"> · {e.actor?.full_name ?? "système"} · {fmtDate(e.created_at)}</span>
                  </div>
                  {e.message && <div className="prewrap">{e.message}</div>}
                </li>
              ))}
            </ol>
            {writable && (
              <div className="row">
                <textarea rows={2} placeholder="Ajouter un commentaire…" value={comment} onChange={(e) => setComment(e.target.value)} />
                <button className="btn" disabled={!comment.trim() || action.busy}
                  onClick={async () => (await mutate("/comments", { message: comment })) && setComment("")}>Publier</button>
              </div>
            )}
          </Card>

          {can("ai:use") && (
            <Card title="Assistant IA" actions={<button className="btn-ghost" disabled={action.busy} onClick={() => void triage()}>Proposer un triage</button>}>
              {suggestions.data?.length ? suggestions.data.map((s) => (
                <SuggestionCard key={s.id} s={s} onReviewed={() => { void suggestions.reload(); void reload(); }} />
              )) : <div className="muted">Aucune suggestion. L'IA ne modifie jamais l'incident sans validation.</div>}
            </Card>
          )}
        </div>

        <div className="stack">
          {writable && (
            <Card title="Actions">
              <div className="form">
                <label>Transition de statut
                  <input placeholder="Commentaire (facultatif)" value={statusComment} onChange={(e) => setStatusComment(e.target.value)} />
                </label>
                <div className="row wrap">
                  {NEXT_STATUSES[inc.status]?.map((s) => (
                    <button key={s} className="btn-ghost" disabled={action.busy} onClick={() => void setStatus(s)}>
                      → {label(STATUS, s)}{s === "closed" && inc.severity === "critical" ? " (approbation)" : ""}
                    </button>
                  ))}
                </div>
                <label>Assigné à
                  <select value={inc.assignee?.id ?? ""} onChange={(e) => void mutate("/assign", { assignee_id: e.target.value || null })}>
                    <option value="">— non assigné —</option>
                    {assignees.data?.map((u) => <option key={u.id} value={u.id}>{u.full_name}</option>)}
                  </select>
                </label>
                <div className="grid2">
                  <label>Sévérité
                    <select value={inc.severity} onChange={(e) => void mutate("", { severity: e.target.value }, "PATCH")}>
                      {Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  </label>
                  <label>Catégorie
                    <select value={inc.category} onChange={(e) => void mutate("", { category: e.target.value }, "PATCH")}>
                      {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  </label>
                </div>
                <label>Playbook
                  <select value={inc.playbook_id ?? ""} onChange={(e) => void mutate("", { playbook_id: e.target.value || null }, "PATCH")}>
                    <option value="">— aucun —</option>
                    {playbooks.data?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                  </select>
                </label>
              </div>
            </Card>
          )}

          {can("incident:escalate") && (
            <Card title="Escalade">
              <div className="form">
                <div className="row wrap">
                  <select value={escalation.to_level} onChange={(e) => setEscalation({ ...escalation, to_level: e.target.value })}>
                    <option value="">Niveau…</option>
                    {LEVELS.filter((l) => LEVELS.indexOf(l) > LEVELS.indexOf(inc.escalation_level)).map((l) => <option key={l}>{l}</option>)}
                  </select>
                  <input placeholder="Motif" value={escalation.reason} onChange={(e) => setEscalation({ ...escalation, reason: e.target.value })} />
                  <button className="btn-ghost" disabled={!escalation.to_level || escalation.reason.length < 5 || action.busy}
                    onClick={async () => (await mutate("/escalate", escalation)) && setEscalation({ to_level: "", reason: "" })}>Escalader</button>
                </div>
                {inc.escalation_level !== "external" && can("decision:request") && (
                  <button className="btn-warn" onClick={() => setDialog("external_escalation")}>Escalade externe (CERT national)…</button>
                )}
              </div>
            </Card>
          )}

          <Card title="Indicateurs de compromission">
            {inc.iocs.length === 0 ? <div className="muted">Aucun IOC lié.</div> : (
              <ul className="ioc-list">
                {inc.iocs.map((i) => <li key={i.id}><span className="tag">{i.type}</span> <code>{i.value}</code> <TlpBadge value={i.tlp} /></li>)}
              </ul>
            )}
            {can("intel:write") && (
              <div className="row">
                <input placeholder="IP, domaine, URL, hash, e-mail, n° de téléphone" value={ioc} onChange={(e) => setIoc(e.target.value)} />
                <button className="btn-ghost" disabled={!ioc.trim() || action.busy} onClick={() => void addIoc()}>Lier</button>
              </div>
            )}
          </Card>

          {playbookSteps.length > 0 && (
            <Card title={`Playbook — ${playbook.data?.name}`}>
              <ol className="steps">
                {playbookSteps.map((s, n) => (
                  <li key={n}>
                    <span className="tag">{s.phase}</span> <strong>{s.title}</strong>
                    {s.requires_approval && <span className="badge st-triaged">validation requise</span>}
                    <div className="muted small">{s.detail}</div>
                  </li>
                ))}
              </ol>
            </Card>
          )}
        </div>
      </div>
      {dialog && <DecisionDialog incident={inc} type={dialog} onClose={() => setDialog(null)} onDone={() => void reload()} />}
    </div>
  );
}

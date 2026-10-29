import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { BarList, SEVERITY_COLORS } from "../components/charts";
import { Card, Empty, ErrorBox, Kpi, Loading, Notice, Pager, Tabs, useAction, useAsync } from "../components/ui";
import { api, download, qs } from "../lib/api";
import { useAuth } from "../lib/auth";
import { CATEGORY, CHANNEL, DECISION, ROLE, SEVERITY, STATUS, fmtDate, fmtDuration, label } from "../lib/format";
import type { AuditEntry, Decision, Org, Page, Stats, UserRow } from "../types";

type TabId = "reports" | "decisions" | "users" | "audit" | "org" | "platform";

function isoDay(d: Date) {
  return d.toISOString().slice(0, 10);
}

function ReportsTab() {
  const today = new Date();
  const [from, setFrom] = useState(isoDay(new Date(today.getTime() - 30 * 86400000)));
  const [to, setTo] = useState(isoDay(today));
  const range = qs({ date_from: `${from}T00:00:00Z`, date_to: `${to}T23:59:59Z` });
  const summary = useAsync(() => api<Stats>(`/analytics/summary${range}`), [range]);
  const [md, setMd] = useState<string | null>(null);
  const action = useAction();
  const s = summary.data;

  return (
    <div className="stack">
      <Card title="Période" actions={
        <>
          <button className="btn-ghost" onClick={() => void download("/incidents/export.csv", "incidents.csv")}>Export incidents (CSV)</button>
          <button className="btn" disabled={action.busy}
            onClick={async () => setMd((await action.run(() => api<string>(`/analytics/executive${range}`, { raw: true }))) ?? null)}>Rapport exécutif</button>
        </>
      }>
        <div className="row">
          <label>Du <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
          <label>au <input type="date" value={to} onChange={(e) => setTo(e.target.value)} /></label>
        </div>
      </Card>
      <ErrorBox message={summary.error ?? action.error} />
      {summary.loading && !s ? <Loading /> : s && (
        <>
          <div className="kpis">
            <Kpi label="Incidents" value={s.totals.incidents} />
            <Kpi label="Respect SLA" value={s.sla_compliance_pct === null ? "n/d" : `${s.sla_compliance_pct} %`} />
            <Kpi label="MTTA" value={fmtDuration(s.mtta_minutes)} />
            <Kpi label="MTTR" value={fmtDuration(s.mttr_minutes)} />
            <Kpi label="Escalades CERT" value={s.totals.escalated_external} />
          </div>
          <div className="grid3">
            <Card title="Par sévérité"><BarList data={s.by_severity} labels={SEVERITY} colors={SEVERITY_COLORS} /></Card>
            <Card title="Par statut"><BarList data={s.by_status} labels={STATUS} /></Card>
            <Card title="Par catégorie"><BarList data={s.by_category} labels={CATEGORY} /></Card>
          </div>
          <Card title="Signalements par canal"><BarList data={s.reports_by_channel} labels={CHANNEL} /></Card>
        </>
      )}
      {md && (
        <Card title="Rapport exécutif (Markdown)" actions={
          <button className="btn-ghost" onClick={() => {
            const url = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
            const a = document.createElement("a");
            a.href = url;
            a.download = `rapport-executif-${from}-${to}.md`;
            a.click();
            URL.revokeObjectURL(url);
          }}>Télécharger</button>
        }>
          <pre className="code report">{md}</pre>
        </Card>
      )}
    </div>
  );
}

function DecisionsTab() {
  const { can, me } = useAuth();
  const [status, setStatus] = useState("pending");
  const { data, error, loading, reload } = useAsync(() => api<Decision[]>(`/decisions${qs({ status })}`), [status]);
  const [comments, setComments] = useState<Record<string, string>>({});
  const action = useAction();

  const review = async (d: Decision, approve: boolean) => {
    if (await action.run(() => api(`/decisions/${d.id}/review`, { body: { approve, comment: comments[d.id] ?? "" } }))) void reload();
  };

  return (
    <Card title="Décisions sensibles (principe des quatre yeux)" actions={
      <select value={status} onChange={(e) => setStatus(e.target.value)}>
        <option value="pending">En attente</option><option value="approved">Approuvées</option>
        <option value="rejected">Rejetées</option><option value="">Toutes</option>
      </select>
    }>
      <Notice>Une décision sensible n'est exécutée qu'après approbation par un analyste habilité distinct du demandeur. Chaque décision est tracée dans le journal d'audit.</Notice>
      <ErrorBox message={error ?? action.error} />
      {loading && !data ? <Loading /> : !data?.length ? <Empty>Aucune décision.</Empty> : (
        <div className="stack">
          {data.map((d) => (
            <div key={d.id} className={`decision dc-${d.status}`}>
              <div className="row">
                <strong>{label(DECISION, d.type)}</strong>
                <span className={`badge dcs-${d.status}`}>{d.status === "pending" ? "En attente" : d.status === "approved" ? "Approuvée" : "Rejetée"}</span>
                {d.target_type === "incident" && d.target_id && <Link to={`/incidents/${d.target_id}`}>voir l'incident ›</Link>}
              </div>
              <div className="muted small">Demandée par {d.requested_by.full_name} le {fmtDate(d.created_at)}</div>
              <p className="prewrap">{d.justification}</p>
              {d.reviewed_by && <div className="small">Examinée par {d.reviewed_by.full_name} le {fmtDate(d.reviewed_at)}{d.review_comment ? ` — « ${d.review_comment} »` : ""}</div>}
              {d.status === "pending" && can("decision:approve") && (
                d.requested_by.id === me?.id ? <div className="muted small">Vous êtes le demandeur : un autre analyste habilité doit statuer.</div> : (
                  <div className="row">
                    <input placeholder="Commentaire" value={comments[d.id] ?? ""} onChange={(e) => setComments({ ...comments, [d.id]: e.target.value })} />
                    <button className="btn" disabled={action.busy} onClick={() => void review(d, true)}>Approuver et exécuter</button>
                    <button className="btn-danger" disabled={action.busy} onClick={() => void review(d, false)}>Rejeter</button>
                  </div>
                )
              )}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function UsersTab() {
  const { me } = useAuth();
  const { data, error, reload } = useAsync(() => api<UserRow[]>("/admin/users"), []);
  const [f, setF] = useState({ email: "", full_name: "", role: "analyst", password: "" });
  const action = useAction();
  const roles = Object.keys(ROLE).filter((r) => r !== "super_admin" || me?.role === "super_admin");

  const create = async (e: FormEvent) => {
    e.preventDefault();
    if (await action.run(() => api("/admin/users", { body: f }))) {
      setF({ email: "", full_name: "", role: "analyst", password: "" });
      void reload();
    }
  };
  const patch = async (u: UserRow, body: Partial<UserRow>) => {
    if (await action.run(() => api(`/admin/users/${u.id}`, { method: "PATCH", body }))) void reload();
  };

  return (
    <div className="stack">
      <Card title="Créer un utilisateur">
        <form className="form" onSubmit={create}>
          <div className="grid2">
            <label>Nom complet<input required value={f.full_name} onChange={(e) => setF({ ...f, full_name: e.target.value })} /></label>
            <label>E-mail<input required type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></label>
            <label>Rôle
              <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
                {roles.map((r) => <option key={r} value={r}>{label(ROLE, r)}</option>)}
              </select>
            </label>
            <label>Mot de passe initial<input required type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })}
              placeholder="12 caractères, majuscule, minuscule, chiffre" /></label>
          </div>
          <button className="btn" disabled={action.busy}>Créer</button>
        </form>
      </Card>
      <ErrorBox message={error ?? action.error} />
      <Card title="Utilisateurs de l'organisation">
        <table className="table">
          <thead><tr><th>Nom</th><th>E-mail</th><th>Rôle</th><th>Dernière connexion</th><th>Statut</th></tr></thead>
          <tbody>
            {data?.map((u) => (
              <tr key={u.id}>
                <td>{u.full_name}</td>
                <td>{u.email}</td>
                <td>
                  <select value={u.role} disabled={u.id === me?.id} onChange={(e) => void patch(u, { role: e.target.value })}>
                    {Object.keys(ROLE).filter((r) => roles.includes(r) || r === u.role).map((r) => <option key={r} value={r}>{label(ROLE, r)}</option>)}
                  </select>
                </td>
                <td>{fmtDate(u.last_login_at)}</td>
                <td>
                  <button className={u.is_active ? "btn-ghost" : "btn-warn"} disabled={u.id === me?.id}
                    onClick={() => void patch(u, { is_active: !u.is_active })}>{u.is_active ? "Actif — désactiver" : "Inactif — réactiver"}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}

function AuditTab() {
  const [page, setPage] = useState(1);
  const [action, setAction] = useState("");
  const { data, error, loading } = useAsync(() => api<Page<AuditEntry>>(`/admin/audit${qs({ action, page, size: 50 })}`), [action, page]);
  const [verify, setVerify] = useState<{ valid: boolean; checked: number; broken_at_id: number | null } | null>(null);
  const run = useAction();
  return (
    <Card title="Journal d'audit (chaîné SHA-256)" actions={
      <>
        <input placeholder="Filtrer par action (ex. incident, auth, pii)" onKeyDown={(e) => {
          if (e.key === "Enter") { setAction((e.target as HTMLInputElement).value); setPage(1); }
        }} />
        <button className="btn" disabled={run.busy} onClick={async () => setVerify((await run.run(() => api<typeof verify>("/admin/audit/verify"))) ?? null)}>Vérifier l'intégrité</button>
      </>
    }>
      {verify && (verify.valid
        ? <Notice tone="ok">Chaîne intègre : {verify.checked} entrées vérifiées.</Notice>
        : <Notice tone="warn">Altération détectée à l'entrée #{verify.broken_at_id} !</Notice>)}
      <ErrorBox message={error ?? run.error} />
      {loading && !data ? <Loading /> : (
        <table className="table small">
          <thead><tr><th>#</th><th>Date</th><th>Acteur</th><th>Action</th><th>Cible</th><th>IP</th><th>Détails</th><th>Empreinte</th></tr></thead>
          <tbody>
            {data?.items.map((e) => (
              <tr key={e.id}>
                <td>{e.id}</td>
                <td>{fmtDate(e.created_at)}</td>
                <td>{e.actor_email ?? <span className="muted">système / public</span>}</td>
                <td className="mono">{e.action}</td>
                <td>{e.target_type ? `${e.target_type}:${e.target_id?.slice(0, 8)}` : ""}</td>
                <td>{e.ip}</td>
                <td className="mono break">{Object.keys(e.details).length ? JSON.stringify(e.details).slice(0, 120) : ""}</td>
                <td className="mono" title={e.hash}>{e.hash.slice(0, 10)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && <Pager page={page} size={50} total={data.total} onPage={setPage} />}
    </Card>
  );
}

function OrgTab() {
  const { data, reload } = useAsync(() => api<Org>("/admin/organization"), []);
  const [retention, setRetention] = useState<number | null>(null);
  const [token, setToken] = useState<{ intake_token: string; webhook_url_template: string } | null>(null);
  const [justification, setJustification] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const action = useAction();
  if (!data) return <Loading />;
  return (
    <div className="grid2">
      <Card title="Protection des données">
        <div className="form">
          <label>Durée de rétention des signalements et incidents clos (jours)
            <input type="number" min={30} max={3650} value={retention ?? data.retention_days} onChange={(e) => setRetention(Number(e.target.value))} />
          </label>
          <button className="btn" disabled={action.busy || retention === null}
            onClick={async () => { if (await action.run(() => api("/admin/organization", { method: "PATCH", body: { retention_days: retention } }))) { setMsg("Rétention enregistrée."); void reload(); } }}>Enregistrer</button>
          <label>Purge / anonymisation des données au-delà de la rétention (décision soumise à approbation)
            <input placeholder="Justification" value={justification} onChange={(e) => setJustification(e.target.value)} />
          </label>
          <button className="btn-warn" disabled={action.busy || justification.length < 10}
            onClick={async () => { if (await action.run(() => api("/decisions", { body: { type: "purge_data", justification } }))) setMsg("Demande de purge soumise à approbation."); }}>Demander la purge</button>
        </div>
      </Card>
      <Card title="Passerelles de signalement (e-mail, SMS, WhatsApp)">
        <p className="small">Le jeton authentifie les passerelles qui transmettent les messages reçus. Il n'est affiché qu'une fois ; seule son empreinte est stockée.</p>
        <button className="btn-warn" disabled={action.busy}
          onClick={async () => setToken((await action.run(() => api<{ intake_token: string; webhook_url_template: string }>("/admin/organization/intake-token", { body: {} }))) ?? null)}>Régénérer le jeton</button>
        {token && (
          <Notice tone="warn">
            <div>Jeton : <code className="break">{token.intake_token}</code></div>
            <div>URL : <code>{token.webhook_url_template}</code> · en-tête <code>X-Intake-Token</code></div>
          </Notice>
        )}
      </Card>
      {msg && <Notice tone="ok">{msg}</Notice>}
      <ErrorBox message={action.error} />
    </div>
  );
}

function PlatformTab() {
  const { data, reload } = useAsync(() => api<Org[]>("/admin/organizations"), []);
  const [f, setF] = useState({ name: "", slug: "", sector: "", country: "", admin_email: "", admin_name: "", admin_password: "" });
  const action = useAction();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  return (
    <div className="grid2">
      <Card title="Organisations">
        <table className="table">
          <thead><tr><th>Nom</th><th>Identifiant</th><th>Secteur</th><th>Pays</th></tr></thead>
          <tbody>{data?.map((o) => <tr key={o.id}><td>{o.name}</td><td className="mono">{o.slug}</td><td>{o.sector}</td><td>{o.country}</td></tr>)}</tbody>
        </table>
      </Card>
      <Card title="Nouvelle organisation">
        <form className="form" onSubmit={async (e) => { e.preventDefault(); if (await action.run(() => api("/admin/organizations", { body: f }))) void reload(); }}>
          <div className="grid2">
            <label>Nom<input required value={f.name} onChange={set("name")} /></label>
            <label>Identifiant (slug)<input required pattern="[a-z0-9-]{2,80}" value={f.slug} onChange={set("slug")} /></label>
            <label>Secteur<input value={f.sector} onChange={set("sector")} /></label>
            <label>Pays<input value={f.country} onChange={set("country")} /></label>
            <label>Nom de l'administrateur<input required value={f.admin_name} onChange={set("admin_name")} /></label>
            <label>E-mail de l'administrateur<input required type="email" value={f.admin_email} onChange={set("admin_email")} /></label>
            <label>Mot de passe initial<input required type="password" value={f.admin_password} onChange={set("admin_password")} /></label>
          </div>
          <ErrorBox message={action.error} />
          <button className="btn" disabled={action.busy}>Créer l'organisation</button>
        </form>
      </Card>
    </div>
  );
}

export default function Admin() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const tabs: { id: TabId; label: string; perm: string }[] = [
    { id: "reports", label: "Rapports & statistiques", perm: "reports:read" },
    { id: "decisions", label: "Décisions", perm: "decision:request" },
    { id: "users", label: "Utilisateurs", perm: "user:manage" },
    { id: "audit", label: "Journal d'audit", perm: "audit:read" },
    { id: "org", label: "Organisation", perm: "org:settings" },
    { id: "platform", label: "Plateforme", perm: "org:manage" },
  ];
  const visible = tabs.filter((t) => can(t.perm));
  const requested = params.get("tab") as TabId | null;
  const tab = visible.find((t) => t.id === requested)?.id ?? visible[0]?.id ?? "reports";
  return (
    <div className="page">
      <div className="page-head"><h1>Rapports, statistiques et administration</h1></div>
      <Tabs value={tab} onChange={(id) => setParams({ tab: id })} tabs={visible} />
      {tab === "reports" && <ReportsTab />}
      {tab === "decisions" && <DecisionsTab />}
      {tab === "users" && <UsersTab />}
      {tab === "audit" && <AuditTab />}
      {tab === "org" && <OrgTab />}
      {tab === "platform" && <PlatformTab />}
    </div>
  );
}

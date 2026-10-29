import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Card, CategoryTag, Empty, ErrorBox, Loading, Modal, Notice, Pager, Tabs, useAction, useAsync } from "../components/ui";
import { api, qs } from "../lib/api";
import { useAuth } from "../lib/auth";
import { CATEGORY, CHANNEL, SEVERITY, fmtDate, label } from "../lib/format";
import type { Incident, IncidentDetail, IntakeReport, Page } from "../types";

const REPORT_STATUS: Record<string, string> = { received: "À trier", converted: "Converti", rejected: "Rejeté" };
const ANALYST_CHANNELS = ["web", "phone", "email", "sms", "whatsapp", "api"];

function NewReport({ onDone }: { onDone: () => void }) {
  const { can } = useAuth();
  const triage = can("report:triage");
  const empty = { channel: "web", subject: "", body: "", category_hint: "", name: "", email: "", phone: "", anonymous: false };
  const [f, setF] = useState(empty);
  const [receipt, setReceipt] = useState<string | null>(null);
  const { busy, error, run } = useAction();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run(() =>
      api<{ tracking_code: string }>("/reports", {
        body: {
          channel: f.channel,
          subject: f.subject,
          body: f.body,
          category_hint: f.category_hint || null,
          is_anonymous: f.anonymous,
          reporter: f.anonymous ? null : { name: f.name || null, email: f.email || null, phone: f.phone || null },
        },
      }),
    );
    if (r) {
      setReceipt(r.tracking_code);
      setF(empty);
      onDone();
    }
  };

  return (
    <Card title="Déclarer un incident">
      {receipt && <Notice tone="ok">Signalement enregistré — code de suivi <strong>{receipt}</strong></Notice>}
      <form className="form" onSubmit={submit}>
        <div className="grid2">
          {triage ? (
            <label>
              Canal de réception
              <select value={f.channel} onChange={set("channel")}>
                {ANALYST_CHANNELS.map((c) => <option key={c} value={c}>{label(CHANNEL, c)}</option>)}
              </select>
            </label>
          ) : (
            <label>Canal<input value="Portail web" disabled /></label>
          )}
          <label>
            Type présumé
            <select value={f.category_hint} onChange={set("category_hint")}>
              <option value="">Classement automatique</option>
              {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
        </div>
        <label>Objet<input required minLength={3} value={f.subject} onChange={set("subject")} /></label>
        <label>Description<textarea required minLength={10} rows={5} value={f.body} onChange={set("body")} /></label>
        <label className="check">
          <input type="checkbox" checked={f.anonymous} onChange={(e) => setF({ ...f, anonymous: e.target.checked })} />
          Déclarant anonyme
        </label>
        {!f.anonymous && (
          <div className="grid3">
            <label>Nom du déclarant<input value={f.name} onChange={set("name")} /></label>
            <label>E-mail<input type="email" value={f.email} onChange={set("email")} /></label>
            <label>Téléphone<input value={f.phone} onChange={set("phone")} /></label>
          </div>
        )}
        <p className="muted small">Les coordonnées sont chiffrées au repos et masquées pour les analystes non habilités.</p>
        <ErrorBox message={error} />
        <button className="btn" disabled={busy}>Enregistrer le signalement</button>
      </form>
    </Card>
  );
}

function ReportModal({ report, onClose, onChanged }: { report: IntakeReport; onClose: () => void; onChanged: () => void }) {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [current, setCurrent] = useState(report);
  const [severity, setSeverity] = useState("medium");
  const [category, setCategory] = useState(report.category_hint ?? "other");
  const [mergeId, setMergeId] = useState("");
  const [reason, setReason] = useState("");
  const action = useAction();
  const open = useAsync(
    () => (can("incident:read") ? api<Page<Incident>>(`/incidents${qs({ open_only: true, size: 100 })}`) : Promise.resolve(null)),
    [],
  );

  const reveal = () =>
    action.run(async () => setCurrent(await api<IntakeReport>(`/reports/${report.id}?reveal=true`)));

  const convert = async () => {
    const inc = await action.run(() =>
      api<IncidentDetail>(`/reports/${report.id}/convert`, {
        body: mergeId ? { merge_into_incident_id: mergeId } : { severity, category },
      }),
    );
    if (inc) {
      onChanged();
      navigate(`/incidents/${inc.id}`);
    }
  };

  const reject = async () => {
    const r = await action.run(() => api<IntakeReport>(`/reports/${report.id}/reject`, { body: { reason } }));
    if (r) {
      onChanged();
      onClose();
    }
  };

  return (
    <Modal title={`Signalement ${current.tracking_code}`} onClose={onClose}>
      <dl className="dl">
        <dt>Canal</dt><dd>{label(CHANNEL, current.channel)}</dd>
        <dt>Reçu le</dt><dd>{fmtDate(current.created_at)}</dd>
        <dt>Pré-classement</dt><dd>{current.category_hint ? <CategoryTag value={current.category_hint} /> : "—"}</dd>
        <dt>Statut</dt><dd>{label(REPORT_STATUS, current.status)}</dd>
        <dt>Déclarant</dt>
        <dd>
          {current.is_anonymous ? <em>Anonyme</em> : (
            <>
              {[current.reporter_name, current.reporter_email, current.reporter_phone].filter(Boolean).join(" · ") || "—"}
              {current.pii_masked && can("pii:read") && (
                <button className="link" onClick={() => void reveal()}> Afficher en clair (action tracée)</button>
              )}
            </>
          )}
        </dd>
      </dl>
      <h3>{current.subject}</h3>
      <p className="prewrap">{current.body}</p>
      {current.rejection_reason && <Notice tone="warn">Motif du rejet : {current.rejection_reason}</Notice>}
      {current.incident_id && <Link to={`/incidents/${current.incident_id}`}>Voir l'incident associé ›</Link>}

      {can("report:triage") && current.status === "received" && (
        <div className="triage-box">
          <h3>Tri</h3>
          <div className="grid3">
            <label>
              Sévérité
              <select value={severity} onChange={(e) => setSeverity(e.target.value)} disabled={!!mergeId}>
                {Object.entries(SEVERITY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </label>
            <label>
              Catégorie
              <select value={category} onChange={(e) => setCategory(e.target.value)} disabled={!!mergeId}>
                {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </label>
            <label>
              Ou rattacher à
              <select value={mergeId} onChange={(e) => setMergeId(e.target.value)}>
                <option value="">— nouvel incident —</option>
                {open.data?.items.map((i) => <option key={i.id} value={i.id}>{i.reference} — {i.title.slice(0, 40)}</option>)}
              </select>
            </label>
          </div>
          <div className="row">
            <button className="btn" disabled={action.busy} onClick={() => void convert()}>
              {mergeId ? "Rattacher à l'incident" : "Créer l'incident"}
            </button>
            <input placeholder="Motif du rejet (spam, doublon…)" value={reason} onChange={(e) => setReason(e.target.value)} />
            <button className="btn-danger" disabled={action.busy || reason.length < 3} onClick={() => void reject()}>Rejeter</button>
          </div>
        </div>
      )}
      <ErrorBox message={action.error} />
    </Modal>
  );
}

function Queue({ refreshKey }: { refreshKey: number }) {
  const { can } = useAuth();
  const [status, setStatus] = useState(can("report:triage") ? "received" : "");
  const [channel, setChannel] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<IntakeReport | null>(null);
  const { data, error, loading, reload } = useAsync(
    () => api<Page<IntakeReport>>(`/reports${qs({ status, channel, page, size: 20 })}`),
    [status, channel, page, refreshKey],
  );

  return (
    <Card
      title={can("report:triage") ? "File de tri des signalements" : "Mes signalements"}
      actions={
        <>
          <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
            <option value="">Tous statuts</option>
            {Object.entries(REPORT_STATUS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select value={channel} onChange={(e) => { setChannel(e.target.value); setPage(1); }}>
            <option value="">Tous canaux</option>
            {Object.entries(CHANNEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </>
      }
    >
      <ErrorBox message={error} />
      {loading && !data ? <Loading /> : data && data.items.length === 0 ? <Empty>Aucun signalement.</Empty> : (
        <table className="table clickable">
          <thead><tr><th>Code</th><th>Canal</th><th>Objet</th><th>Pré-classement</th><th>Statut</th><th>Reçu</th></tr></thead>
          <tbody>
            {data?.items.map((r) => (
              <tr key={r.id} onClick={() => setSelected(r)}>
                <td className="mono">{r.tracking_code}</td>
                <td>{label(CHANNEL, r.channel)}</td>
                <td>{r.subject}</td>
                <td>{r.category_hint ? <CategoryTag value={r.category_hint} /> : "—"}</td>
                <td><span className={`badge rs-${r.status}`}>{label(REPORT_STATUS, r.status)}</span></td>
                <td>{fmtDate(r.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && <Pager page={page} size={20} total={data.total} onPage={setPage} />}
      {selected && <ReportModal report={selected} onClose={() => setSelected(null)} onChanged={() => void reload()} />}
    </Card>
  );
}

function Channels() {
  const { me } = useAuth();
  const slug = me?.organization.slug;
  return (
    <Card title="Canaux de réception">
      <ul className="channels">
        <li><strong>Formulaire public anonyme</strong> — <Link to={`/signaler/${slug}`}>/signaler/{slug}</Link>, avec code de suivi, limitation de débit et piège anti-robots.</li>
        <li><strong>E-mail, SMS, WhatsApp</strong> — passerelles qui appellent <code>POST /api/v1/intake/&#123;email|sms|whatsapp&#125;/{slug}</code> avec l'en-tête <code>X-Intake-Token</code> (régénérable dans l'administration).</li>
        <li><strong>Téléphone</strong> — l'analyste saisit l'appel ci-contre avec le canal « Téléphone ».</li>
        <li><strong>Portail web</strong> — déclaration par les collaborateurs authentifiés.</li>
      </ul>
    </Card>
  );
}

export default function Reporting() {
  const { can } = useAuth();
  const [tab, setTab] = useState<"queue" | "new">(can("report:triage") ? "queue" : "new");
  const [refreshKey, setRefreshKey] = useState(0);
  return (
    <div className="page">
      <div className="page-head"><h1>Signalements multicanal</h1></div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "queue", label: can("report:triage") ? "File de tri" : "Mes signalements" },
        { id: "new", label: "Nouveau signalement" },
      ]} />
      {tab === "queue" ? <Queue refreshKey={refreshKey} /> : (
        <div className="grid2">
          <NewReport onDone={() => setRefreshKey((k) => k + 1)} />
          <Channels />
        </div>
      )}
    </div>
  );
}

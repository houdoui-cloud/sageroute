import { useState, type FormEvent } from "react";
import { Card, Empty, ErrorBox, Loading, Modal, Notice, Pager, SeverityBadge, Tabs, TlpBadge, useAction, useAsync } from "../components/ui";
import { api, download, qs } from "../lib/api";
import { useAuth } from "../lib/auth";
import { TLP, fmtDate } from "../lib/format";
import type { IntelItem, Ioc, Page } from "../types";

const TYPES = ["ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "phone"];

function IocDetail({ ioc, onClose, onChanged }: { ioc: Ioc; onClose: () => void; onChanged: () => void }) {
  const { can } = useAuth();
  const info = useAsync(() => (ioc.is_community ? Promise.resolve(null) : api<Record<string, unknown>>(`/intel/iocs/${ioc.id}/enrich`)), [ioc.id]);
  const [justification, setJustification] = useState("");
  const action = useAction();
  const [done, setDone] = useState<string | null>(null);

  const patch = async (body: Partial<Ioc>) => {
    if (await action.run(() => api(`/intel/iocs/${ioc.id}`, { method: "PATCH", body }))) onChanged();
  };
  const share = async () => {
    const r = await action.run(() => api("/decisions", { body: { type: "share_ioc", target_id: ioc.id, justification } }));
    if (r) setDone("Demande de partage soumise à approbation.");
  };

  return (
    <Modal title={`${ioc.type} — ${ioc.value}`} onClose={onClose}>
      <dl className="dl">
        <dt>TLP</dt><dd><TlpBadge value={ioc.tlp} /></dd>
        <dt>Confiance</dt><dd>{ioc.confidence} %</dd>
        <dt>Source</dt><dd>{ioc.source}</dd>
        <dt>Observations</dt><dd>{ioc.sightings} (de {fmtDate(ioc.first_seen)} à {fmtDate(ioc.last_seen)})</dd>
        <dt>Incidents liés</dt><dd>{ioc.incident_refs.join(", ") || "—"}</dd>
        {ioc.description && (<><dt>Contexte</dt><dd>{ioc.description}</dd></>)}
      </dl>
      {info.data && (
        <>
          <h3>Enrichissement local</h3>
          <pre className="code">{JSON.stringify(info.data, null, 2)}</pre>
        </>
      )}
      {ioc.is_community && <Notice>Indicateur partagé par la communauté — l'organisation source n'est pas divulguée.</Notice>}
      {!ioc.is_community && can("intel:write") && (
        <div className="form">
          <div className="row">
            <label>TLP
              <select value={ioc.tlp} onChange={(e) => void patch({ tlp: e.target.value })}>
                {TLP.map((t) => <option key={t}>{t}</option>)}
              </select>
            </label>
            <button className="btn-ghost" onClick={() => void patch({ is_active: !ioc.is_active })}>
              {ioc.is_active ? "Désactiver" : "Réactiver"}
            </button>
          </div>
          {!ioc.shared && ioc.tlp !== "red" && can("decision:request") && (
            <>
              <label>Partager avec la communauté (TLP:CLEAR, soumis à approbation)
                <input placeholder="Justification (10 caractères min.)" value={justification} onChange={(e) => setJustification(e.target.value)} />
              </label>
              <button className="btn-warn" disabled={justification.length < 10 || action.busy} onClick={() => void share()}>Demander le partage</button>
            </>
          )}
          {ioc.shared && <Notice tone="ok">Partagé avec la communauté.</Notice>}
          {done && <Notice tone="ok">{done}</Notice>}
        </div>
      )}
      <ErrorBox message={action.error} />
    </Modal>
  );
}

function IocTab() {
  const { can } = useAuth();
  const [f, setF] = useState({ type: "", tlp: "", q: "", community: false, page: 1 });
  const [selected, setSelected] = useState<Ioc | null>(null);
  const [draft, setDraft] = useState({ value: "", tlp: "amber", confidence: 60, description: "" });
  const [bulk, setBulk] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const action = useAction();
  const { data, error, loading, reload } = useAsync(
    () => api<Page<Ioc>>(`/intel/iocs${qs({ type: f.type, tlp: f.tlp, q: f.q, include_community: f.community || undefined, page: f.page, size: 50 })}`),
    [f],
  );

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const r = await action.run(() => api<Ioc>("/intel/iocs", { body: draft }));
    if (r) {
      setMsg(`IOC ${r.type} enregistré (${r.sightings} observation${r.sightings > 1 ? "s" : ""}).`);
      setDraft({ ...draft, value: "", description: "" });
      void reload();
    }
  };
  const importBulk = async () => {
    const r = await action.run(() => api<{ extracted: number; created: number; updated: number }>("/intel/iocs/import", { body: { text: bulk, source: "import manuel" } }));
    if (r) {
      setMsg(`${r.extracted} indicateurs extraits : ${r.created} nouveaux, ${r.updated} mis à jour.`);
      setBulk("");
      void reload();
    }
  };

  return (
    <div className="stack">
      {can("intel:write") && (
        <div className="grid2">
          <Card title="Ajouter un indicateur">
            <form className="form" onSubmit={create}>
              <label>Valeur (type détecté automatiquement, formes « défangées » acceptées)
                <input required value={draft.value} onChange={(e) => setDraft({ ...draft, value: e.target.value })} placeholder="hxxp://exemple[.]example/login" />
              </label>
              <div className="grid2">
                <label>TLP
                  <select value={draft.tlp} onChange={(e) => setDraft({ ...draft, tlp: e.target.value })}>{TLP.map((t) => <option key={t}>{t}</option>)}</select>
                </label>
                <label>Confiance (%)
                  <input type="number" min={0} max={100} value={draft.confidence} onChange={(e) => setDraft({ ...draft, confidence: Number(e.target.value) })} />
                </label>
              </div>
              <label>Contexte<input value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} /></label>
              <button className="btn" disabled={action.busy}>Enregistrer</button>
            </form>
          </Card>
          <Card title="Import en masse">
            <textarea rows={6} value={bulk} onChange={(e) => setBulk(e.target.value)} placeholder="Collez un bulletin, une liste ou un CSV : les indicateurs sont extraits automatiquement." />
            <button className="btn" disabled={!bulk.trim() || action.busy} onClick={() => void importBulk()}>Extraire et importer</button>
          </Card>
        </div>
      )}
      {msg && <Notice tone="ok">{msg}</Notice>}
      <ErrorBox message={action.error} />
      <Card title="Indicateurs de compromission" actions={
        <>
          <button className="btn-ghost" onClick={() => void download("/intel/iocs/export?fmt=csv", "iocs.csv")}>CSV</button>
          <button className="btn-ghost" onClick={() => void download("/intel/iocs/export?fmt=json", "iocs.json")}>JSON</button>
        </>
      }>
        <div className="filters">
          <input placeholder="Rechercher une valeur" onKeyDown={(e) => e.key === "Enter" && setF({ ...f, q: (e.target as HTMLInputElement).value, page: 1 })} />
          <select value={f.type} onChange={(e) => setF({ ...f, type: e.target.value, page: 1 })}>
            <option value="">Tous types</option>{TYPES.map((t) => <option key={t}>{t}</option>)}
          </select>
          <select value={f.tlp} onChange={(e) => setF({ ...f, tlp: e.target.value, page: 1 })}>
            <option value="">Tous TLP</option>{TLP.map((t) => <option key={t}>{t}</option>)}
          </select>
          <label className="check"><input type="checkbox" checked={f.community} onChange={(e) => setF({ ...f, community: e.target.checked, page: 1 })} /> Inclure la communauté</label>
        </div>
        <ErrorBox message={error} />
        {loading && !data ? <Loading /> : data && data.items.length === 0 ? <Empty>Aucun indicateur.</Empty> : (
          <table className="table clickable">
            <thead><tr><th>Type</th><th>Valeur</th><th>TLP</th><th>Confiance</th><th>Source</th><th>Obs.</th><th>Incidents</th><th>Vu le</th></tr></thead>
            <tbody>
              {data?.items.map((i) => (
                <tr key={i.id} onClick={() => setSelected(i)}>
                  <td><span className="tag">{i.type}</span></td>
                  <td className="mono break">{i.value}{i.shared && " ⇄"}</td>
                  <td><TlpBadge value={i.tlp} /></td>
                  <td>{i.confidence} %</td>
                  <td>{i.source}</td>
                  <td>{i.sightings}</td>
                  <td>{i.incident_refs.join(", ")}</td>
                  <td>{fmtDate(i.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {data && <Pager page={f.page} size={50} total={data.total} onPage={(p) => setF({ ...f, page: p })} />}
      </Card>
      {selected && <IocDetail ioc={selected} onClose={() => setSelected(null)} onChanged={() => { setSelected(null); void reload(); }} />}
    </div>
  );
}

interface MatchResult {
  extracted: number;
  matches: number;
  indicators: { type: string; value: string; known: Ioc[] }[];
}

function MatchTab() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<MatchResult | null>(null);
  const action = useAction();
  return (
    <Card title="Analyser un texte (journal, courriel, bulletin)">
      <textarea rows={8} value={text} onChange={(e) => setText(e.target.value)}
        placeholder="Collez des en-têtes de courriel, des journaux ou un message suspect…" />
      <button className="btn" disabled={!text.trim() || action.busy}
        onClick={async () => setResult((await action.run(() => api<MatchResult>("/intel/match", { body: { text } }))) ?? null)}>Rechercher les correspondances</button>
      <ErrorBox message={action.error} />
      {result && (
        <>
          <Notice tone={result.matches ? "warn" : "ok"}>{result.extracted} indicateur(s) extrait(s), {result.matches} déjà connu(s).</Notice>
          <table className="table">
            <thead><tr><th>Type</th><th>Valeur</th><th>Statut</th></tr></thead>
            <tbody>
              {result.indicators.map((i) => (
                <tr key={i.type + i.value} className={i.known.length ? "row-breach" : ""}>
                  <td><span className="tag">{i.type}</span></td>
                  <td className="mono break">{i.value}</td>
                  <td>{i.known.length ? i.known.map((k) => `${k.is_community ? "communauté" : k.source} (confiance ${k.confidence} %)`).join(" ; ") : <span className="muted">inconnu</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </Card>
  );
}

function FeedTab() {
  const { can } = useAuth();
  const [tag, setTag] = useState("");
  const { data, error, loading, reload } = useAsync(() => api<IntelItem[]>(`/intel/feed${qs({ tag })}`), [tag]);
  const action = useAction();
  const tags = Array.from(new Set((data ?? []).flatMap((i) => i.tags))).sort();
  return (
    <Card title="Veille OSINT et bulletins" actions={
      <>
        <select value={tag} onChange={(e) => setTag(e.target.value)}>
          <option value="">Tous les thèmes</option>{tags.map((t) => <option key={t}>{t}</option>)}
        </select>
        {can("intel:write") && <button className="btn-ghost" disabled={action.busy}
          onClick={async () => { await action.run(() => api("/intel/feed/sync", { body: {} })); void reload(); }}>Synchroniser les flux</button>}
      </>
    }>
      <p className="muted small">Flux fictifs embarqués hors ligne (aucune requête vers Internet). En production, brancher MISP, OpenCTI ou les bulletins du CERT national.</p>
      <ErrorBox message={error ?? action.error} />
      {loading && !data ? <Loading /> : (
        <div className="feed">
          {data?.map((i) => (
            <article key={i.id} className="feed-item">
              <header className="row">
                <SeverityBadge value={i.severity} /> <strong>{i.title}</strong>
              </header>
              <div className="muted small">{i.source} · {i.region} · {fmtDate(i.published_at)}</div>
              <p>{i.summary}</p>
              <div className="row wrap">
                {i.tags.map((t) => <span key={t} className="tag">{t}</span>)}
                {i.indicators.map((x) => <code key={x.value} className="small">{x.value}</code>)}
              </div>
            </article>
          ))}
        </div>
      )}
    </Card>
  );
}

export default function Intel() {
  const [tab, setTab] = useState<"iocs" | "match" | "feed">("iocs");
  return (
    <div className="page">
      <div className="page-head"><h1>Intelligence cyber &amp; OSINT</h1></div>
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "iocs", label: "Indicateurs (IOC)" },
        { id: "match", label: "Analyse de texte" },
        { id: "feed", label: "Veille OSINT" },
      ]} />
      {tab === "iocs" && <IocTab />}
      {tab === "match" && <MatchTab />}
      {tab === "feed" && <FeedTab />}
    </div>
  );
}

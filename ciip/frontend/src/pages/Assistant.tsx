import { useState } from "react";
import { Card, Empty, ErrorBox, Notice, SeverityBadge, Tabs, useAction, useAsync } from "../components/ui";
import { api, qs } from "../lib/api";
import { useAuth } from "../lib/auth";
import { CATEGORY, fmtDate, label } from "../lib/format";
import type { Incident, Page, Playbook, PlaybookStep, Suggestion } from "../types";

const SUGGESTION_STATUS: Record<string, string> = {
  proposed: "En attente de validation",
  validated: "Validée",
  rejected: "Rejetée",
  informational: "Informatif",
};

function Steps({ steps }: { steps: PlaybookStep[] }) {
  return (
    <ol className="steps">
      {steps.map((s, n) => (
        <li key={n}>
          <span className="tag">{s.phase}</span> <strong>{s.title}</strong>
          {s.requires_approval && <span className="badge st-triaged">validation requise</span>}
          <div className="muted small">{s.detail}</div>
        </li>
      ))}
    </ol>
  );
}

export function SuggestionCard({ s, onReviewed }: { s: Suggestion; onReviewed?: (updated: Suggestion) => void }) {
  const { can } = useAuth();
  const [comment, setComment] = useState("");
  const action = useAction();
  const o = s.output;
  const review = async (approve: boolean) => {
    const updated = await action.run(() => api<Suggestion>(`/ai/suggestions/${s.id}/review`, { body: { approve, comment } }));
    if (updated) onReviewed?.(updated);
  };
  return (
    <div className={`suggestion sg-${s.status}`}>
      <div className="row">
        <strong>{s.kind === "triage" ? "Triage" : s.kind === "playbook" ? "Playbook" : "Réponse"}</strong>
        <span className="tag">{s.engine === "rules" ? "moteur de règles local" : s.engine}</span>
        <span className="tag">confiance {Math.round(s.confidence * 100)} %</span>
        <span className={`badge sgs-${s.status}`}>{label(SUGGESTION_STATUS, s.status)}</span>
        <span className="muted small">{fmtDate(s.created_at)}</span>
      </div>
      {s.kind === "triage" && (
        <>
          <p>Catégorie proposée : <strong>{label(CATEGORY, o.category)}</strong> · sévérité <SeverityBadge value={o.severity} /></p>
          <ul>{(o.rationale as string[] | undefined)?.map((r) => <li key={r}>{r}</li>)}</ul>
          {o.recommended_playbook && <p>Playbook recommandé : <em>{o.recommended_playbook}</em></p>}
          {(o.next_steps as string[] | undefined)?.length ? <p>Premières actions : {(o.next_steps as string[]).join(" → ")}</p> : null}
          {(o.indicators as { type: string; value: string }[] | undefined)?.length ? (
            <p className="small">Indicateurs repérés : {(o.indicators as { value: string }[]).map((i) => <code key={i.value}>{i.value} </code>)}</p>
          ) : null}
        </>
      )}
      {s.kind === "playbook" && (
        <>
          <p><strong>{o.name}</strong> — {o.description}</p>
          <Steps steps={o.steps as PlaybookStep[]} />
        </>
      )}
      {s.kind === "answer" && <p className="prewrap">{o.answer}</p>}
      <details className="small">
        <summary>Texte transmis au modèle (après expurgation des données personnelles)</summary>
        <pre className="code">{s.prompt_redacted}</pre>
      </details>
      <p className="muted small">{o.disclaimer}</p>
      {s.review_comment && <p className="small">Commentaire de l'analyste : {s.review_comment}</p>}
      {s.status === "proposed" && (can("ai:validate") ? (
        <div className="row">
          <input placeholder="Commentaire de validation" value={comment} onChange={(e) => setComment(e.target.value)} />
          <button className="btn" disabled={action.busy} onClick={() => void review(true)}>
            {s.kind === "triage" ? "Valider et appliquer" : "Valider et publier"}
          </button>
          <button className="btn-danger" disabled={action.busy} onClick={() => void review(false)}>Rejeter</button>
        </div>
      ) : <Notice>Validation par un analyste habilité requise.</Notice>)}
      <ErrorBox message={action.error} />
    </div>
  );
}

function Workbench() {
  const [mode, setMode] = useState<"triage" | "playbook" | "ask">("triage");
  const [text, setText] = useState("");
  const [incidentId, setIncidentId] = useState("");
  const [category, setCategory] = useState("phishing");
  const [results, setResults] = useState<Suggestion[]>([]);
  const action = useAction();
  const incidents = useAsync(() => api<Page<Incident>>(`/incidents${qs({ open_only: true, size: 100 })}`), []);

  const go = async () => {
    const body =
      mode === "triage" ? { incident_id: incidentId || null, text: incidentId ? null : text } :
      mode === "playbook" ? { category, context: text, incident_id: incidentId || null } :
      { question: text, incident_id: incidentId || null };
    const path = mode === "triage" ? "/ai/triage" : mode === "playbook" ? "/ai/playbook" : "/ai/ask";
    const r = await action.run(() => api<Suggestion>(path, { body }));
    if (r) setResults([r, ...results]);
  };

  const disabled = action.busy || (mode === "triage" ? !incidentId && text.length < 5 : mode === "ask" ? text.length < 3 : false);

  return (
    <div className="grid2">
      <Card title="Demander à l'assistant">
        <Tabs value={mode} onChange={setMode} tabs={[
          { id: "triage", label: "Triage" }, { id: "playbook", label: "Générer un playbook" }, { id: "ask", label: "Question" },
        ]} />
        <div className="form">
          <label>Incident (facultatif)
            <select value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
              <option value="">— aucun / texte libre —</option>
              {incidents.data?.items.map((i) => <option key={i.id} value={i.id}>{i.reference} — {i.title.slice(0, 50)}</option>)}
            </select>
          </label>
          {mode === "playbook" && (
            <label>Catégorie
              <select value={category} onChange={(e) => setCategory(e.target.value)}>
                {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select>
            </label>
          )}
          {!(mode === "triage" && incidentId) && (
            <label>{mode === "triage" ? "Description à qualifier" : mode === "playbook" ? "Contexte (facultatif)" : "Votre question"}
              <textarea rows={6} value={text} onChange={(e) => setText(e.target.value)} />
            </label>
          )}
          <button className="btn" disabled={disabled} onClick={() => void go()}>{action.busy ? "Analyse…" : "Lancer"}</button>
          <ErrorBox message={action.error} />
        </div>
      </Card>
      <Card title="Résultats">
        {results.length === 0 ? <Empty>Les propositions apparaîtront ici.</Empty> :
          results.map((s) => <SuggestionCard key={s.id} s={s} onReviewed={(u) => setResults(results.map((x) => (x.id === u.id ? u : x)))} />)}
      </Card>
    </div>
  );
}

function Queue() {
  const { data, error, reload } = useAsync(() => api<Suggestion[]>("/ai/suggestions?status=proposed"), []);
  return (
    <Card title="Propositions en attente de validation">
      <ErrorBox message={error} />
      {data?.length ? data.map((s) => <SuggestionCard key={s.id} s={s} onReviewed={() => void reload()} />) : <Empty>Aucune proposition en attente.</Empty>}
    </Card>
  );
}

function Library() {
  const { data } = useAsync(() => api<Playbook[]>("/playbooks"), []);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Card title="Bibliothèque de playbooks">
      {data?.map((p) => (
        <div key={p.id} className="playbook">
          <button className="link" onClick={() => setOpen(open === p.id ? null : p.id)}>
            {p.name}
          </button>{" "}
          <span className="tag">{label(CATEGORY, p.category)}</span>
          {p.organization_id ? <span className="tag">organisation</span> : <span className="tag">référence</span>}
          {p.generated_by_ai && <span className="tag">IA validée</span>}
          {open === p.id && (<><p className="muted small">{p.description}</p><Steps steps={p.steps} /></>)}
        </div>
      ))}
    </Card>
  );
}

export default function Assistant() {
  const [tab, setTab] = useState<"work" | "queue" | "library">("work");
  const status = useAsync(() => api<{ enabled: boolean; reachable: boolean; model: string; model_available?: boolean }>("/ai/status"), []);
  const s = status.data;
  return (
    <div className="page">
      <div className="page-head"><h1>Assistant IA — triage et playbooks</h1></div>
      {s && (
        <Notice tone={s.reachable && s.model_available ? "ok" : "warn"}>
          {s.reachable && s.model_available
            ? <>LLM local actif : <code>{s.model}</code> (Ollama). Aucune donnée ne quitte votre infrastructure.</>
            : <>LLM local {s.enabled ? "injoignable ou modèle absent" : "désactivé"} : l'assistant utilise le moteur de règles déterministe.</>}
          {" "}Les données personnelles sont expurgées avant analyse ; toute proposition doit être validée par un analyste habilité.
        </Notice>
      )}
      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "work", label: "Atelier" }, { id: "queue", label: "À valider" }, { id: "library", label: "Playbooks" },
      ]} />
      {tab === "work" && <Workbench />}
      {tab === "queue" && <Queue />}
      {tab === "library" && <Library />}
    </div>
  );
}

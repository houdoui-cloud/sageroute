import { useEffect, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { ErrorBox, Notice, useAction } from "../components/ui";
import { api } from "../lib/api";
import { CATEGORY } from "../lib/format";

/** Anonymous portal (no account): submit a report, or track one by code. */
export default function PublicReport() {
  const { slug } = useParams();
  const [org, setOrg] = useState<{ name: string } | null>(null);
  const [form, setForm] = useState({ subject: "", body: "", category_hint: "", name: "", email: "", phone: "", website: "" });
  const [receipt, setReceipt] = useState<{ tracking_code: string; message: string } | null>(null);
  const [code, setCode] = useState("");
  const [tracked, setTracked] = useState<{ tracking_code: string; label: string; received_at: string } | null>(null);
  const submitAction = useAction();
  const trackAction = useAction();

  useEffect(() => {
    if (slug) api<{ name: string }>(`/public/organizations/${slug}`).then(setOrg).catch(() => setOrg(null));
  }, [slug]);

  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const hasContact = form.name || form.email || form.phone;
    const r = await submitAction.run(() =>
      api<{ tracking_code: string; message: string }>(`/public/${slug}/reports`, {
        body: {
          subject: form.subject,
          body: form.body,
          category_hint: form.category_hint || null,
          reporter: hasContact ? { name: form.name || null, email: form.email || null, phone: form.phone || null } : null,
          website: form.website || null,
        },
      }),
    );
    if (r) setReceipt(r);
  };

  const track = async (e: FormEvent) => {
    e.preventDefault();
    const r = await trackAction.run(() => api<typeof tracked>(`/public/reports/${encodeURIComponent(code.trim())}`));
    if (r) setTracked(r);
  };

  return (
    <div className="login-page">
      <div className="login-card wide">
        <div className="brand brand-lg">
          <span className="brand-mark">CIIP</span>
          <span className="brand-sub">Portail de signalement</span>
        </div>

        {slug && (
          <>
            <h1>Signaler un incident{org ? ` à ${org.name}` : ""}</h1>
            {!org && <Notice tone="warn">Organisation inconnue.</Notice>}
            {receipt ? (
              <Notice tone="ok">
                <p>{receipt.message}</p>
                <p className="tracking">{receipt.tracking_code}</p>
                <Link to="/suivi">Suivre ce signalement</Link>
              </Notice>
            ) : (
              org && (
                <form className="form" onSubmit={submit}>
                  <Notice>
                    Les champs d'identité sont facultatifs. Vos coordonnées sont chiffrées et ne sont visibles que
                    des analystes habilités. Ne transmettez jamais de mot de passe ni de code secret.
                  </Notice>
                  <label>Objet<input required minLength={3} maxLength={300} value={form.subject} onChange={set("subject")} /></label>
                  <label>
                    Type d'incident (si connu)
                    <select value={form.category_hint} onChange={set("category_hint")}>
                      <option value="">Je ne sais pas</option>
                      {Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                    </select>
                  </label>
                  <label>
                    Que s'est-il passé ?
                    <textarea required minLength={10} rows={6} value={form.body} onChange={set("body")}
                      placeholder="Date, ce que vous avez constaté, liens ou numéros suspects…" />
                  </label>
                  <div className="grid3">
                    <label>Nom (facultatif)<input value={form.name} onChange={set("name")} /></label>
                    <label>E-mail (facultatif)<input type="email" value={form.email} onChange={set("email")} /></label>
                    <label>Téléphone (facultatif)<input value={form.phone} onChange={set("phone")} /></label>
                  </div>
                  {/* Honeypot: hidden from humans. */}
                  <input className="hp" tabIndex={-1} autoComplete="off" value={form.website} onChange={set("website")} aria-hidden />
                  <ErrorBox message={submitAction.error} />
                  <button className="btn" disabled={submitAction.busy}>Envoyer le signalement</button>
                </form>
              )
            )}
            <hr />
          </>
        )}

        <h2>Suivre un signalement</h2>
        <form className="form inline" onSubmit={track}>
          <input placeholder="SIG-XXXXXXXX" value={code} onChange={(e) => setCode(e.target.value)} required />
          <button className="btn" disabled={trackAction.busy}>Consulter</button>
        </form>
        <ErrorBox message={trackAction.error} />
        {tracked && (
          <Notice tone="ok">
            <strong>{tracked.tracking_code}</strong> — {tracked.label}
          </Notice>
        )}
        <p className="muted small"><Link to="/login">Espace professionnel</Link></p>
        <p className="demo-flag">Démonstrateur — données fictives.</p>
      </div>
    </div>
  );
}

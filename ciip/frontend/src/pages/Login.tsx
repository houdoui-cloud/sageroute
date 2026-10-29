import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { ErrorBox, useAction } from "../components/ui";
import { useAuth } from "../lib/auth";

const DEMO_ACCOUNTS = [
  ["analyste@bfs.example", "Analyste (Banque Fictive du Sahel)"],
  ["lead@bfs.example", "Analyste habilité — valide les décisions"],
  ["admin@bfs.example", "Administrateur de l'organisation"],
  ["declarant@bfs.example", "Déclarant (agent d'agence)"],
  ["auditeur@bfs.example", "Auditeur (lecture seule)"],
  ["analyste@mdn.example", "Analyste (Ministère Démo du Numérique)"],
  ["superadmin@ciip.example", "Opérateur de la plateforme"],
];

export default function Login() {
  const { me, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { busy, error, run } = useAction();

  if (me) return <Navigate to="/" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await run(async () => {
      await login(email, password);
      return true;
    });
    if (ok) navigate((location.state as { from?: string } | null)?.from ?? "/", { replace: true });
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="brand brand-lg">
          <span className="brand-mark">CIIP</span>
          <span className="brand-sub">Cyber Incident &amp; Intelligence Platform</span>
        </div>
        <p className="muted">Plateforme de réponse aux incidents et de renseignement cyber pour les organisations africaines.</p>
        <form onSubmit={submit} className="form">
          <label>
            Adresse e-mail
            <input type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <label>
            Mot de passe
            <input type="password" autoComplete="current-password" required value={password}
              onChange={(e) => setPassword(e.target.value)} />
          </label>
          <ErrorBox message={error} />
          <button className="btn" disabled={busy}>{busy ? "Connexion…" : "Se connecter"}</button>
        </form>
        <details className="demo-accounts">
          <summary>Comptes de démonstration (mot de passe : <code>DemoCiip2026!</code>)</summary>
          <ul>
            {DEMO_ACCOUNTS.map(([mail, desc]) => (
              <li key={mail}>
                <button type="button" className="link" onClick={() => { setEmail(mail); setPassword("DemoCiip2026!"); }}>
                  {mail}
                </button>{" "}
                <span className="muted">— {desc}</span>
              </li>
            ))}
          </ul>
        </details>
        <p className="muted small">
          Vous êtes victime ou témoin d'un incident ? <Link to="/signaler/bfs">Signaler anonymement</Link> ·{" "}
          <Link to="/suivi">Suivre un signalement</Link>
        </p>
        <p className="demo-flag">Démonstrateur — toutes les données sont fictives.</p>
      </div>
    </div>
  );
}

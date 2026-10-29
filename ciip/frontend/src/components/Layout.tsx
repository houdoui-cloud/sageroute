import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { ROLE, label } from "../lib/format";

const NAV = [
  { to: "/", label: "Supervision", icon: "◉", perm: "dashboard:read" },
  { to: "/signalements", label: "Signalements", icon: "✉", perm: "report:submit" },
  { to: "/incidents", label: "Incidents", icon: "⚑", perm: "incident:read" },
  { to: "/intelligence", label: "Intelligence & IOC", icon: "◈", perm: "intel:read" },
  { to: "/assistant", label: "Assistant IA", icon: "✦", perm: "ai:use" },
  { to: "/administration", label: "Rapports & admin", icon: "▤", perm: "reports:read" },
];

export default function Layout() {
  const { me, logout, can } = useAuth();
  const navigate = useNavigate();
  // Leave explicitly so the next person does not land on the previous user's page.
  const signOut = async () => {
    await logout();
    navigate("/login", { replace: true });
  };
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">CIIP</span>
          <span className="brand-sub">Cyber Incident &amp; Intelligence</span>
        </div>
        <nav>
          {NAV.filter((n) => can(n.perm) || (n.to === "/administration" && can("audit:read"))).map((n) => (
            <NavLink key={n.to} to={n.to} end={n.to === "/"} className={({ isActive }) => (isActive ? "nav active" : "nav")}>
              <span className="nav-icon" aria-hidden>{n.icon}</span>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="demo-flag">Démonstrateur — données fictives</div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div>
            <strong>{me?.organization.name}</strong>
            <span className="muted"> · {me?.organization.sector}</span>
          </div>
          <div className="topbar-user">
            <span>{me?.full_name}</span>
            <span className="tag">{label(ROLE, me?.role)}</span>
            <button className="btn-ghost" onClick={() => void signOut()}>Déconnexion</button>
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

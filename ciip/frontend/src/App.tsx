import type { ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import Layout from "./components/Layout";
import { Loading } from "./components/ui";
import { useAuth } from "./lib/auth";
import Admin from "./pages/Admin";
import Assistant from "./pages/Assistant";
import Dashboard from "./pages/Dashboard";
import IncidentDetail from "./pages/IncidentDetail";
import Incidents from "./pages/Incidents";
import Intel from "./pages/Intel";
import Login from "./pages/Login";
import PublicReport from "./pages/PublicReport";
import Reporting from "./pages/Reporting";

function Protected({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Loading />;
  if (!me) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

function Guard({ perm, children }: { perm: string | string[]; children: ReactNode }) {
  const { can } = useAuth();
  const perms = Array.isArray(perm) ? perm : [perm];
  if (!perms.some(can)) return <div className="alert alert-warn">Accès non autorisé pour votre rôle.</div>;
  return <>{children}</>;
}

function Home() {
  const { can } = useAuth();
  return can("dashboard:read") ? <Dashboard /> : <Navigate to="/signalements" replace />;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/signaler/:slug" element={<PublicReport />} />
      <Route path="/suivi" element={<PublicReport />} />
      <Route element={<Protected><Layout /></Protected>}>
        <Route index element={<Home />} />
        <Route path="signalements" element={<Guard perm="report:submit"><Reporting /></Guard>} />
        <Route path="incidents" element={<Guard perm="incident:read"><Incidents /></Guard>} />
        <Route path="incidents/:id" element={<Guard perm="incident:read"><IncidentDetail /></Guard>} />
        <Route path="intelligence" element={<Guard perm="intel:read"><Intel /></Guard>} />
        <Route path="assistant" element={<Guard perm="ai:use"><Assistant /></Guard>} />
        <Route path="administration" element={<Guard perm={["reports:read", "audit:read"]}><Admin /></Guard>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

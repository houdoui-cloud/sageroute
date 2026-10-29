import { useEffect } from "react";
import { Link } from "react-router-dom";
import { BarList, Gauge, SEVERITY_COLORS, TrendChart } from "../components/charts";
import { Card, ErrorBox, Kpi, Loading, StatusBadge, useAsync } from "../components/ui";
import { api } from "../lib/api";
import { CATEGORY, CHANNEL, SEVERITY, fmtDate, fmtDuration } from "../lib/format";
import type { Stats } from "../types";

export default function Dashboard() {
  const { data, error, loading, reload } = useAsync(() => api<Stats>("/analytics/dashboard"), []);

  // Live supervision: refresh every 60 s.
  useEffect(() => {
    const t = window.setInterval(() => void reload(), 60_000);
    return () => window.clearInterval(t);
  }, [reload]);

  if (loading && !data) return <Loading />;
  if (!data) return <ErrorBox message={error} />;
  const t = data.totals;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Supervision des incidents</h1>
        <span className="muted">30 derniers jours · actualisation automatique</span>
      </div>
      <ErrorBox message={error} />

      <div className="kpis">
        <Kpi label="Incidents ouverts" value={t.open} hint={`${t.incidents} sur la période`} />
        <Kpi label="Critiques ouverts" value={t.critical_open} tone={t.critical_open ? "danger" : undefined} />
        <Kpi label="Hors SLA (ouverts)" value={t.sla_breached_open} tone={t.sla_breached_open ? "warn" : undefined} />
        <Kpi label="MTTA" value={fmtDuration(data.mtta_minutes)} hint="délai moyen de prise en charge" />
        <Kpi label="MTTR" value={fmtDuration(data.mttr_minutes)} hint="délai moyen de résolution" />
        <Kpi label="Signalements à trier" value={<Link to="/signalements">{t.reports_pending}</Link>} />
        <Kpi label="Décisions en attente" value={<Link to="/administration?tab=decisions">{t.decisions_pending}</Link>}
          tone={t.decisions_pending ? "info" : undefined} />
        <Kpi label="IOC actifs" value={<Link to="/intelligence">{t.iocs_active}</Link>} />
      </div>

      <div className="grid2">
        <Card title="Tendance des incidents déclarés">
          <TrendChart points={data.trend} />
        </Card>
        <Card title="Respect des SLA">
          <div className="gauge-wrap">
            <Gauge value={data.sla_compliance_pct} label="Respect des SLA" />
            <div className="muted small">
              Part des incidents de la période dont la prise en charge et la résolution respectent les délais
              (critique : 15 min / 4 h · élevée : 1 h / 24 h · moyenne : 4 h / 72 h · faible : 24 h / 7 j).
            </div>
          </div>
        </Card>
      </div>

      <div className="grid3">
        <Card title="Ouverts par sévérité">
          <BarList data={data.open_by_severity} labels={SEVERITY} colors={SEVERITY_COLORS} />
        </Card>
        <Card title="Menaces principales">
          <BarList data={data.by_category} labels={CATEGORY} />
        </Card>
        <Card title="Canaux de signalement">
          <BarList data={data.reports_by_channel} labels={CHANNEL} />
        </Card>
      </div>

      <Card title="Incidents majeurs en cours" actions={<Link to="/incidents?open_only=1">Tous les incidents ›</Link>}>
        {data.recent_critical.length === 0 ? (
          <div className="muted pad">Aucun incident critique ou élevé ouvert.</div>
        ) : (
          <table className="table">
            <thead><tr><th>Référence</th><th>Titre</th><th>Statut</th><th>Déclaré le</th></tr></thead>
            <tbody>
              {data.recent_critical.map((i) => (
                <tr key={i.id}>
                  <td><Link to={`/incidents/${i.id}`}>{i.reference}</Link></td>
                  <td>{i.title}</td>
                  <td><StatusBadge value={i.status} /></td>
                  <td>{fmtDate(i.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

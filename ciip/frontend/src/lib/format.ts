export const SEVERITY: Record<string, string> = {
  critical: "Critique",
  high: "Élevée",
  medium: "Moyenne",
  low: "Faible",
};

export const STATUS: Record<string, string> = {
  new: "Nouveau",
  triaged: "Qualifié",
  in_progress: "En traitement",
  contained: "Contenu",
  resolved: "Résolu",
  closed: "Clôturé",
  rejected: "Rejeté",
};

export const NEXT_STATUSES: Record<string, string[]> = {
  new: ["triaged", "in_progress", "rejected"],
  triaged: ["in_progress", "rejected"],
  in_progress: ["contained", "resolved"],
  contained: ["in_progress", "resolved"],
  resolved: ["closed", "in_progress"],
  closed: ["in_progress"],
  rejected: ["triaged"],
};

export const CATEGORY: Record<string, string> = {
  phishing: "Hameçonnage",
  malware: "Logiciel malveillant",
  ransomware: "Rançongiciel",
  ddos: "Déni de service",
  data_breach: "Fuite de données",
  unauthorized_access: "Accès non autorisé",
  account_compromise: "Compte compromis",
  mobile_money_fraud: "Fraude mobile money",
  defacement: "Défiguration",
  social_engineering: "Ingénierie sociale",
  other: "Autre",
};

export const CHANNEL: Record<string, string> = {
  web: "Portail web",
  public_form: "Formulaire public",
  email: "E-mail",
  sms: "SMS",
  whatsapp: "WhatsApp",
  phone: "Téléphone",
  api: "API",
};

export const ROLE: Record<string, string> = {
  super_admin: "Opérateur plateforme",
  org_admin: "Administrateur",
  lead_analyst: "Analyste habilité",
  analyst: "Analyste",
  reporter: "Déclarant",
  auditor: "Auditeur",
};

export const DECISION: Record<string, string> = {
  close_critical_incident: "Clôture d'un incident critique",
  external_escalation: "Escalade vers le CERT national",
  share_ioc: "Partage communautaire d'un IOC",
  purge_data: "Purge des données (rétention)",
};

export const EVENT: Record<string, string> = {
  created: "Création",
  status_change: "Changement de statut",
  assignment: "Assignation",
  comment: "Commentaire",
  escalation: "Escalade",
  severity_change: "Sévérité",
  updated: "Modification",
  report_merged: "Signalement",
  ai_validated: "IA validée",
};

export const TLP = ["clear", "green", "amber", "amber+strict", "red"];

export function label(map: Record<string, string>, key: string | null | undefined): string {
  if (!key) return "—";
  return map[key] ?? key;
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function fmtDuration(minutes: number | null | undefined): string {
  if (minutes === null || minutes === undefined) return "n/d";
  if (minutes < 120) return `${Math.round(minutes)} min`;
  if (minutes < 60 * 48) return `${(minutes / 60).toFixed(1)} h`;
  return `${(minutes / 1440).toFixed(1)} j`;
}

/** "dans 2 h" / "il y a 3 j" relative to now. */
export function relative(iso: string | null, now: Date = new Date()): string {
  if (!iso) return "—";
  const diff = new Date(iso).getTime() - now.getTime();
  const abs = Math.abs(diff) / 60000;
  const txt = abs < 60 ? `${Math.round(abs)} min` : abs < 2880 ? `${Math.round(abs / 60)} h` : `${Math.round(abs / 1440)} j`;
  return diff >= 0 ? `dans ${txt}` : `il y a ${txt}`;
}

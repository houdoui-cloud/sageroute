export type Severity = "critical" | "high" | "medium" | "low";
export type IncidentStatus = "new" | "triaged" | "in_progress" | "contained" | "resolved" | "closed" | "rejected";

export interface Org {
  id: string;
  name: string;
  slug: string;
  sector: string;
  country: string;
  retention_days: number;
  is_active: boolean;
}

export interface Me {
  id: string;
  email: string;
  full_name: string;
  role: string;
  organization: Org;
  permissions: string[];
}

export interface UserBrief {
  id: string;
  full_name: string;
  role: string;
}

export interface UserRow extends UserBrief {
  email: string;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

export interface Incident {
  id: string;
  reference: string;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  status: IncidentStatus;
  source_channel: string;
  escalation_level: string;
  affected_assets: string[];
  tags: string[];
  playbook_id: string | null;
  assignee: UserBrief | null;
  sla_ack_due: string | null;
  sla_resolve_due: string | null;
  acknowledged_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
  sla_breached: boolean;
}

export interface IncidentEvent {
  id: string;
  kind: string;
  message: string;
  data: Record<string, unknown>;
  created_at: string;
  actor: UserBrief | null;
}

export interface IocBrief {
  id: string;
  type: string;
  value: string;
  tlp: string;
  confidence: number;
}

export interface IncidentDetail extends Incident {
  events: IncidentEvent[];
  iocs: IocBrief[];
  pending_decisions: number;
}

export interface IntakeReport {
  id: string;
  tracking_code: string;
  channel: string;
  subject: string;
  body: string;
  category_hint: string | null;
  is_anonymous: boolean;
  status: string;
  rejection_reason: string | null;
  incident_id: string | null;
  created_at: string;
  reporter_name: string | null;
  reporter_email: string | null;
  reporter_phone: string | null;
  pii_masked: boolean;
}

export interface Ioc extends IocBrief {
  source: string;
  description: string;
  tags: string[];
  is_active: boolean;
  shared: boolean;
  sightings: number;
  first_seen: string;
  last_seen: string;
  is_community: boolean;
  incident_refs: string[];
}

export interface IntelItem {
  id: string;
  source: string;
  title: string;
  summary: string;
  severity: Severity;
  tags: string[];
  region: string;
  indicators: { type: string; value: string }[];
  published_at: string;
}

export interface Suggestion {
  id: string;
  incident_id: string | null;
  kind: "triage" | "playbook" | "answer";
  engine: string;
  prompt_redacted: string;
  output: Record<string, any>;
  confidence: number;
  status: "proposed" | "validated" | "rejected" | "informational";
  review_comment: string | null;
  reviewed_at: string | null;
  created_at: string;
}

export interface PlaybookStep {
  phase: string;
  title: string;
  detail: string;
  requires_approval: boolean;
}

export interface Playbook {
  id: string;
  organization_id: string | null;
  name: string;
  category: string;
  description: string;
  steps: PlaybookStep[];
  status: string;
  generated_by_ai: boolean;
}

export interface Decision {
  id: string;
  type: string;
  target_type: string;
  target_id: string | null;
  payload: Record<string, unknown>;
  justification: string;
  status: "pending" | "approved" | "rejected";
  requested_by: UserBrief;
  reviewed_by: UserBrief | null;
  review_comment: string | null;
  reviewed_at: string | null;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  actor_email: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  details: Record<string, unknown>;
  created_at: string;
  hash: string;
}

export interface Stats {
  period: { from: string; to: string };
  totals: Record<string, number>;
  mtta_minutes: number | null;
  mttr_minutes: number | null;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_category: Record<string, number>;
  open_by_severity: Record<string, number>;
  reports_by_channel: Record<string, number>;
  trend: { date: string; count: number }[];
  sla_compliance_pct: number | null;
  recent_critical: { id: string; reference: string; title: string; status: string; created_at: string }[];
}

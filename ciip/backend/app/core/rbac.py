"""Role → permission mapping. Endpoints declare permissions, never roles."""

from enum import StrEnum


class Role(StrEnum):
    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    LEAD_ANALYST = "lead_analyst"
    ANALYST = "analyst"
    REPORTER = "reporter"
    AUDITOR = "auditor"


class Perm(StrEnum):
    DASHBOARD_READ = "dashboard:read"
    INCIDENT_READ = "incident:read"
    INCIDENT_WRITE = "incident:write"
    INCIDENT_ESCALATE = "incident:escalate"
    REPORT_SUBMIT = "report:submit"
    REPORT_TRIAGE = "report:triage"
    PII_READ = "pii:read"
    INTEL_READ = "intel:read"
    INTEL_WRITE = "intel:write"
    AI_USE = "ai:use"
    AI_VALIDATE = "ai:validate"
    DECISION_REQUEST = "decision:request"
    DECISION_APPROVE = "decision:approve"
    REPORTS_READ = "reports:read"
    AUDIT_READ = "audit:read"
    USER_MANAGE = "user:manage"
    ORG_SETTINGS = "org:settings"
    PLAYBOOK_WRITE = "playbook:write"
    ORG_MANAGE = "org:manage"  # platform-level: create/list organisations


_ANALYST = {
    Perm.DASHBOARD_READ, Perm.INCIDENT_READ, Perm.INCIDENT_WRITE, Perm.INCIDENT_ESCALATE,
    Perm.REPORT_SUBMIT, Perm.REPORT_TRIAGE, Perm.INTEL_READ, Perm.INTEL_WRITE,
    Perm.AI_USE, Perm.DECISION_REQUEST, Perm.REPORTS_READ,
}
_LEAD = _ANALYST | {Perm.AI_VALIDATE, Perm.DECISION_APPROVE, Perm.PII_READ, Perm.PLAYBOOK_WRITE}
_ORG_ADMIN = _LEAD | {Perm.AUDIT_READ, Perm.USER_MANAGE, Perm.ORG_SETTINGS}

ROLE_PERMISSIONS: dict[Role, frozenset[Perm]] = {
    Role.SUPER_ADMIN: frozenset(Perm),
    Role.ORG_ADMIN: frozenset(_ORG_ADMIN),
    Role.LEAD_ANALYST: frozenset(_LEAD),
    Role.ANALYST: frozenset(_ANALYST),
    Role.REPORTER: frozenset({Perm.REPORT_SUBMIT}),
    Role.AUDITOR: frozenset({
        Perm.DASHBOARD_READ, Perm.INCIDENT_READ, Perm.INTEL_READ,
        Perm.REPORTS_READ, Perm.AUDIT_READ,
    }),
}


def has_perm(role: str, perm: Perm) -> bool:
    return perm in ROLE_PERMISSIONS.get(Role(role), frozenset())


def permissions_for(role: str) -> list[str]:
    return sorted(p.value for p in ROLE_PERMISSIONS.get(Role(role), frozenset()))

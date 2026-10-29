"""French display labels for server-generated text (timeline, reports)."""

SEVERITY_FR = {"critical": "critique", "high": "élevée", "medium": "moyenne", "low": "faible"}

STATUS_FR = {
    "new": "nouveau", "triaged": "qualifié", "in_progress": "en traitement", "contained": "contenu",
    "resolved": "résolu", "closed": "clôturé", "rejected": "rejeté",
}

CATEGORY_FR = {
    "phishing": "Hameçonnage", "malware": "Logiciel malveillant", "ransomware": "Rançongiciel",
    "ddos": "Déni de service", "data_breach": "Fuite de données", "unauthorized_access": "Accès non autorisé",
    "account_compromise": "Compte compromis", "mobile_money_fraud": "Fraude mobile money",
    "defacement": "Défiguration", "social_engineering": "Ingénierie sociale", "other": "Autre",
}

CHANNEL_FR = {
    "web": "Portail web", "public_form": "Formulaire public", "email": "E-mail", "sms": "SMS",
    "whatsapp": "WhatsApp", "phone": "Téléphone", "api": "API",
}


def fr(table: dict[str, str], key: str | None) -> str:
    return table.get(key or "", key or "—")

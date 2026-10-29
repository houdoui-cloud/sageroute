"""Triage and playbook assistant.

Two engines:
* Ollama (local LLM) — nothing leaves the organisation's infrastructure;
* a deterministic rules engine, used when Ollama is disabled/unreachable and
  as a sanity check on the LLM output (unknown categories are rejected).

Every result is a *proposal*. Applying it requires a validating analyst.
"""

import json
import logging
import re
from dataclasses import dataclass

import httpx

from app.core.config import get_settings
from app.core.privacy import redact
from app.models import Category, Severity
from app.services import ioc as ioc_svc
from app.services.playbook_library import REFERENCE_PLAYBOOKS

log = logging.getLogger("ciip.ai")

DISCLAIMER = (
    "Proposition générée automatiquement : elle doit être examinée et validée "
    "par un analyste habilité avant toute action."
)

_KEYWORDS: dict[Category, list[str]] = {
    Category.RANSOMWARE: ["rançon", "ransom", "chiffré", "chiffrés", "encrypted", ".lock", "bitcoin", "rançongiciel", "lockbit"],
    Category.PHISHING: ["phishing", "hameçonnage", "lien suspect", "faux site", "identifiants", "mot de passe demandé", "spoof", "usurpation de la banque"],
    Category.MOBILE_MONEY_FRAUD: ["mobile money", "momo", "orange money", "wave", "m-pesa", "transfert frauduleux", "code de retrait", "airtime", "sim swap"],
    Category.DDOS: ["ddos", "déni de service", "indisponible", "saturé", "trafic massif", "flood"],
    Category.DATA_BREACH: ["fuite", "exfiltration", "base de données publiée", "données personnelles", "leak", "dump", "vendues sur"],
    Category.MALWARE: ["malware", "virus", "trojan", "cheval de troie", "exécutable", "macro", "infecté", "antivirus"],
    Category.ACCOUNT_COMPROMISE: ["compte piraté", "compte compromis", "connexion inhabituelle", "mfa", "prise de contrôle", "compromission du compte"],
    Category.UNAUTHORIZED_ACCESS: ["accès non autorisé", "intrusion", "brute force", "force brute", "élévation de privilèges", "vpn", "rdp"],
    Category.DEFACEMENT: ["défiguration", "defacement", "page d'accueil modifiée", "site modifié", "hacked by"],
    Category.SOCIAL_ENGINEERING: ["se faisant passer", "faux technicien", "appel frauduleux", "arnaque au président", "fovi", "ingénierie sociale"],
}

_BASE_SEVERITY: dict[Category, Severity] = {
    Category.RANSOMWARE: Severity.CRITICAL,
    Category.DATA_BREACH: Severity.HIGH,
    Category.DDOS: Severity.HIGH,
    Category.MOBILE_MONEY_FRAUD: Severity.HIGH,
    Category.UNAUTHORIZED_ACCESS: Severity.HIGH,
    Category.ACCOUNT_COMPROMISE: Severity.MEDIUM,
    Category.MALWARE: Severity.MEDIUM,
    Category.PHISHING: Severity.MEDIUM,
    Category.DEFACEMENT: Severity.MEDIUM,
    Category.SOCIAL_ENGINEERING: Severity.MEDIUM,
    Category.OTHER: Severity.LOW,
}

_AGGRAVATING = ["production", "tous les postes", "serveur", "clients", "massif", "paiement", "core banking",
                "données personnelles", "ministère", "plusieurs agences", "propagation", "domain admin", "sauvegardes"]

_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@dataclass
class AiResult:
    engine: str
    output: dict
    confidence: float
    prompt_redacted: str


def _bump(sev: Severity, steps: int) -> Severity:
    return _ORDER[min(_ORDER.index(sev) + steps, len(_ORDER) - 1)]


def rules_triage(text: str) -> dict:
    low = text.lower()
    scores = {cat: sum(1 for k in kws if k in low) for cat, kws in _KEYWORDS.items()}
    best = max(scores, key=lambda c: scores[c])
    category = best if scores[best] > 0 else Category.OTHER
    hits = [k for k in _KEYWORDS.get(category, []) if k in low]
    aggravating = [k for k in _AGGRAVATING if k in low]
    severity = _bump(_BASE_SEVERITY[category], 1 if len(aggravating) >= 2 else 0)
    top, total = scores.get(category, 0), sum(scores.values()) or 1
    # Many matching keywords, mostly from one category → higher confidence.
    confidence = 0.2 if category == Category.OTHER else round(min(0.9, 0.35 + 0.15 * top) * top / total, 2)
    rationale = []
    if hits:
        rationale.append(f"Mots-clés caractéristiques détectés : {', '.join(hits)}")
    if aggravating:
        rationale.append(f"Facteurs aggravants : {', '.join(aggravating)}")
    if not rationale:
        rationale.append("Aucun motif caractéristique : classement par défaut, à qualifier manuellement")
    playbook = REFERENCE_PLAYBOOKS.get(category)
    return {
        "category": category.value,
        "severity": severity.value,
        "summary": text.strip().split("\n")[0][:200],
        "rationale": rationale,
        "recommended_playbook": playbook["name"] if playbook else None,
        "next_steps": [s["title"] for s in (playbook["steps"][:3] if playbook else [])],
        "confidence": max(confidence, 0.2),
    }


def _ollama(prompt: str) -> dict | None:
    s = get_settings()
    if not s.ai_use_ollama:
        return None
    try:
        resp = httpx.post(
            f"{s.ollama_url.rstrip('/')}/api/generate",
            json={"model": s.ollama_model, "prompt": prompt, "stream": False, "format": "json",
                  "options": {"temperature": 0.1}},
            timeout=s.ollama_timeout_seconds,
        )
        resp.raise_for_status()
        return json.loads(resp.json().get("response", "{}"))
    except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
        log.warning("Ollama indisponible, repli sur le moteur de règles : %s", exc)
        return None


_SYSTEM = (
    "Tu es un assistant d'analyste SOC/CSIRT pour une organisation africaine. "
    "Réponds UNIQUEMENT en JSON valide, en français. Ne prends aucune décision : "
    "tu proposes, un analyste humain valide."
)


def triage(text: str) -> AiResult:
    clean = redact(text)
    base = rules_triage(clean)
    indicators = [{"type": t.value, "value": v} for t, v in ioc_svc.extract(clean)][:50]
    prompt = (
        f"{_SYSTEM}\nCatégories possibles : {', '.join(c.value for c in Category)}.\n"
        f"Sévérités possibles : {', '.join(s.value for s in Severity)}.\n"
        'Format : {"category":..., "severity":..., "summary":"...", "rationale":["..."], '
        '"next_steps":["..."], "confidence":0.0-1.0}\n\n'
        f"Signalement :\n{clean}"
    )
    llm = _ollama(prompt)
    engine = "rules"
    output = base
    if llm:
        cat, sev = llm.get("category"), llm.get("severity")
        if cat in Category._value2member_map_ and sev in Severity._value2member_map_:
            engine = f"ollama:{get_settings().ollama_model}"
            output = {
                **base,
                "category": cat,
                "severity": sev,
                "summary": str(llm.get("summary", base["summary"]))[:500],
                "rationale": [str(r) for r in llm.get("rationale", [])][:10] or base["rationale"],
                "next_steps": [str(r) for r in llm.get("next_steps", [])][:10] or base["next_steps"],
                "confidence": float(llm.get("confidence", 0.5)),
                "rules_engine_opinion": {"category": base["category"], "severity": base["severity"]},
            }
            pb = REFERENCE_PLAYBOOKS.get(Category(cat))
            output["recommended_playbook"] = pb["name"] if pb else None
    output["indicators"] = indicators
    output["disclaimer"] = DISCLAIMER
    return AiResult(engine, output, float(output.get("confidence", 0.3)), clean)


def generate_playbook(category: Category, context: str) -> AiResult:
    clean = redact(context)
    ref = REFERENCE_PLAYBOOKS.get(category) or REFERENCE_PLAYBOOKS[Category.OTHER]
    prompt = (
        f"{_SYSTEM}\nRédige un playbook de réponse à incident pour la catégorie « {category.value} », "
        "selon les phases NIST (préparation, détection, confinement, éradication, rétablissement, retour d'expérience).\n"
        'Format : {"name":"...", "description":"...", "steps":[{"phase":"...", "title":"...", "detail":"...", "requires_approval":false}]}\n'
        f"Contexte (expurgé) : {clean or 'aucun'}"
    )
    llm = _ollama(prompt)
    if llm and isinstance(llm.get("steps"), list) and llm["steps"]:
        steps = [
            {
                "phase": str(st.get("phase", ""))[:60],
                "title": str(st.get("title", ""))[:200],
                "detail": str(st.get("detail", ""))[:2000],
                "requires_approval": bool(st.get("requires_approval", False)),
            }
            for st in llm["steps"][:30]
            if isinstance(st, dict) and st.get("title")
        ]
        if steps:
            output = {"name": str(llm.get("name") or ref["name"])[:200],
                      "description": str(llm.get("description", ""))[:2000],
                      "category": category.value, "steps": steps, "disclaimer": DISCLAIMER}
            return AiResult(f"ollama:{get_settings().ollama_model}", output, 0.6, prompt)
    output = {
        "name": f"{ref['name']} (adapté)",
        "description": ref["description"] + (f" Contexte : {clean[:300]}" if clean else ""),
        "category": category.value,
        "steps": ref["steps"],
        "disclaimer": DISCLAIMER,
    }
    return AiResult("rules", output, 0.5, prompt)


def answer(question: str, context: str) -> AiResult:
    clean_q, clean_ctx = redact(question), redact(context)
    prompt = (
        f"{_SYSTEM}\nContexte de l'incident (expurgé) :\n{clean_ctx or 'aucun'}\n\n"
        f'Question : {clean_q}\nFormat : {{"answer":"...", "references":["..."]}}'
    )
    llm = _ollama(prompt)
    if llm and llm.get("answer"):
        return AiResult(f"ollama:{get_settings().ollama_model}",
                        {"answer": str(llm["answer"])[:5000],
                         "references": [str(r) for r in llm.get("references", [])][:10],
                         "disclaimer": DISCLAIMER}, 0.5, prompt)
    tri = rules_triage(clean_ctx + "\n" + clean_q)
    pb = REFERENCE_PLAYBOOKS.get(Category(tri["category"]))
    lines = [f"Le moteur local (sans LLM) rapproche cette situation de la catégorie « {tri['category']} »."]
    if pb:
        lines.append(f"Playbook de référence : {pb['name']}. Étapes prioritaires :")
        lines += [f"{i}. {s['title']} — {s['detail']}" for i, s in enumerate(pb["steps"][:4], 1)]
    if re.search(r"\b(notifier|déclarer|autorité|régulateur|cert)\b", clean_q.lower()):
        lines.append("La notification à une autorité externe est une décision sensible : "
                     "créez une demande d'escalade externe soumise à approbation.")
    return AiResult("rules", {"answer": "\n".join(lines), "references": [pb["name"]] if pb else [],
                              "disclaimer": DISCLAIMER}, 0.3, prompt)


def ollama_status() -> dict:
    s = get_settings()
    if not s.ai_use_ollama:
        return {"enabled": False, "reachable": False, "model": s.ollama_model}
    try:
        resp = httpx.get(f"{s.ollama_url.rstrip('/')}/api/tags", timeout=3)
        models = [m.get("name") for m in resp.json().get("models", [])]
        return {"enabled": True, "reachable": True, "model": s.ollama_model,
                "model_available": s.ollama_model in models, "models": models}
    except (httpx.HTTPError, ValueError):
        return {"enabled": True, "reachable": False, "model": s.ollama_model}

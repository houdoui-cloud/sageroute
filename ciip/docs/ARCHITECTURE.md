# Architecture — Cyber Incident & Intelligence Platform (CIIP) V1

> Démonstrateur destiné aux entreprises et institutions africaines (banques,
> opérateurs mobiles, ministères, CERT/CSIRT sectoriels). **Toutes les données
> livrées sont fictives** (organisations, personnes, adresses IP issues des
> plages de documentation RFC 5737, domaines `.example`).

## 1. Vue d'ensemble

```
                 ┌────────────────────────────────────────────────────────┐
  Navigateur ───▶│ Frontend React + TypeScript (Vite, servi par Nginx)    │
                 │  6 écrans + portail public de signalement              │
                 └───────────────┬────────────────────────────────────────┘
                                 │ HTTPS /api/v1 (JWT Bearer)
                 ┌───────────────▼────────────────────────────────────────┐
  Canaux ───────▶│ API FastAPI                                            │
  e-mail / SMS / │  ├─ auth (JWT access+refresh, verrouillage, révocation)│
  WhatsApp /     │  ├─ RBAC (rôles → permissions) + isolation organisation│
  formulaire     │  ├─ modules métier (incidents, signalements, intel, IA,│
  public         │  │   rapports, administration, décisions 4-yeux)        │
                 │  ├─ audit chaîné (SHA-256)                              │
                 │  └─ protection des données (chiffrement PII, masquage,  │
                 │      expurgation avant IA, rétention)                   │
                 └──────┬──────────────────┬──────────────────┬───────────┘
                        │                  │                  │
                ┌───────▼──────┐   ┌───────▼──────┐   ┌───────▼──────────┐
                │ PostgreSQL 16│   │ Redis 7      │   │ Ollama (LLM local)│
                │ données +    │   │ rate-limit,  │   │ triage, playbooks │
                │ audit        │   │ révocation   │   │ repli : moteur de │
                │ (Alembic)    │   │ JWT, cache   │   │ règles déterministe│
                └──────────────┘   └──────────────┘   └──────────────────┘
```

Aucune donnée ne quitte l'infrastructure : le LLM tourne localement via Ollama
(souveraineté des données), et le moteur de règles prend le relais si Ollama est
indisponible, ce qui garde la plateforme utilisable hors connexion.

## 2. Modules et écrans

| # | Écran | Module backend | Points clés |
|---|-------|----------------|-------------|
| 1 | Supervision | `api/stats.py` | KPI, MTTA/MTTR, SLA dépassés, tendances 30 j, cache Redis |
| 2 | Signalement multicanal | `api/intake.py` | Web, formulaire public anonyme (code de suivi), webhooks e-mail/SMS/WhatsApp, saisie téléphone ; conversion en incident ou rejet |
| 3 | Incidents | `api/incidents.py` | Tickets `INC-AAAA-NNNN`, cycle de vie contrôlé, SLA par sévérité, assignation, commentaires, chronologie, escalades L1→L3→externe |
| 4 | Intelligence | `api/intel.py` | IOC typés et normalisés, TLP, liaison aux incidents, extraction/correspondance dans un texte, flux OSINT fictifs, partage communautaire |
| 5 | Assistant IA | `api/ai.py` | Triage, génération de playbooks, questions sur un incident ; **toute suggestion est une proposition** à valider |
| 6 | Rapports & administration | `api/reports.py`, `api/admin.py` | Synthèse périodique, export CSV, rapport exécutif, utilisateurs, organisations, journal d'audit, rétention |

Transverse : `api/decisions.py` — circuit de validation « quatre yeux ».

## 3. Modèle de sécurité

### 3.1 Authentification
* Mots de passe hachés **bcrypt** ; politique : 12 caractères min., majuscule, minuscule, chiffre.
* Jeton d'accès JWT HS256 de 15 min + jeton de rafraîchissement de 7 jours, chacun avec un `jti`.
* Déconnexion = `jti` placé en liste de révocation Redis jusqu'à expiration.
* Verrouillage du compte 15 min après 5 échecs consécutifs.

### 3.2 Rôles et permissions (`app/core/rbac.py`)

| Rôle | Description |
|------|-------------|
| `super_admin` | Opérateur de la plateforme ; gère les organisations ; peut agir dans une organisation via l'en-tête `X-Organization-Id` (audité). |
| `org_admin` | Administre son organisation (utilisateurs, paramètres), dispose de tous les droits métier. |
| `lead_analyst` | **Analyste habilité** : approuve les décisions sensibles et valide les suggestions IA. |
| `analyst` | Traite incidents, signalements et IOC ; demande les décisions sensibles. |
| `reporter` | Déclare des incidents et suit ses propres signalements. |
| `auditor` | Lecture seule + journal d'audit. |

### 3.3 Isolation des organisations
* Toute table métier porte `organization_id`.
* L'organisation est **déduite du jeton**, jamais du corps de la requête.
* Les accès passent par `scoped_get()` / `scoped_query()` (`app/deps.py`) : un
  objet d'une autre organisation renvoie **404** (pas de fuite d'existence).
* Seuls les IOC explicitement partagés (TLP:CLEAR, partage approuvé) sont visibles
  des autres organisations, **sans** l'identité de l'organisation source.
* Tests dédiés : `tests/test_isolation.py`.
* Évolution V2 : Row-Level Security PostgreSQL en défense en profondeur.

### 3.4 Décisions sensibles (principe des quatre yeux)
Les actions suivantes ne s'exécutent **qu'après approbation** par un utilisateur
disposant de `decision:approve` (lead_analyst / org_admin), **distinct du demandeur** :

| Type | Effet à l'approbation |
|------|----------------------|
| `close_critical_incident` | Clôture d'un incident critique |
| `external_escalation` | Escalade vers le CERT national (fictif) |
| `share_ioc` | Partage communautaire d'un IOC (TLP:CLEAR) |
| `purge_data` | Purge/anonymisation des données au-delà de la rétention |

Les suggestions IA (`ai_suggestions`) restent à l'état `proposed` tant qu'un
analyste habilité ne les a pas validées ; l'IA ne modifie jamais un incident seule.

### 3.5 Traçabilité
* Table `audit_logs` : acteur, organisation, action, cible, IP, détails.
* Chaque entrée contient `prev_hash` et `hash = SHA-256(prev_hash ‖ contenu canonique)` :
  toute modification a posteriori est détectée par `GET /admin/audit/verify`.
* Sont tracés : connexions (réussies/échouées), lectures de PII, créations,
  modifications, transitions, escalades, décisions, validations IA, exports.

### 3.6 Protection des données
* Coordonnées des déclarants (nom, e-mail, téléphone) **chiffrées au repos**
  (Fernet/AES-128-CBC + HMAC) ; affichées masquées sauf permission `pii:read`,
  et chaque lecture en clair est auditée.
* **Expurgation** (e-mails, téléphones, IBAN, cartes, n° d'identité) avant tout envoi au LLM.
* Rétention configurable par organisation ; purge via décision approuvée.
* En-têtes de sécurité HTTP, CORS restreint, limitation de débit des endpoints publics,
  jetons d'ingestion par organisation pour les webhooks (comparaison à temps constant).
* Conçu pour faciliter la conformité aux lois de protection des données
  (ex. Convention de Malabo, lois nationales type CDP Sénégal, ARTCI Côte d'Ivoire, NDPA Nigeria).

## 4. Données

Tables principales (migration `alembic/versions/0001_initial.py`) :
`organizations`, `users`, `incidents`, `incident_events`, `escalations`,
`intake_reports`, `iocs`, `incident_iocs`, `intel_items`, `playbooks`,
`ai_suggestions`, `decision_requests`, `audit_logs`.

## 5. Cycle de vie d'un incident

```
new ──▶ triaged ──▶ in_progress ──▶ contained ──▶ resolved ──▶ closed
  │                     ▲  │                         │
  └──────▶ rejected     └──┴─────── (réouverture) ◀──┘
```
Transitions contrôlées par `app/services/incidents.py::ALLOWED_TRANSITIONS`.
SLA (prise en charge / résolution) : critique 15 min / 4 h, élevée 1 h / 24 h,
moyenne 4 h / 72 h, faible 24 h / 7 j.

## 6. Feuille de route

* **V1 (ce dépôt)** : six modules fonctionnels, données fictives.
* **V1.1** : notifications (e-mail/SMS), pièces jointes avec antivirus, MFA TOTP.
* **V2** : RLS PostgreSQL, SSO (OIDC), STIX/TAXII 2.1, connecteurs MISP/OpenCTI,
  corrélation SIEM, multilingue (anglais, portugais, arabe, swahili).

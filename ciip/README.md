# Cyber Incident & Intelligence Platform — V1

Plateforme de gestion des incidents cyber et de renseignement sur la menace,
conçue pour les entreprises et institutions africaines (banques, opérateurs
mobiles, administrations, CERT/CSIRT sectoriels).

> **Démonstrateur : toutes les données sont fictives.** Organisations
> (« Banque Fictive du Sahel », « Ministère Démo du Numérique », « République
> de Kalanda »), personnes, IP (plages de documentation RFC 5737), domaines
> `.example`, flux OSINT et CERT national sont inventés.

**Pile** : React 18 + TypeScript (Vite) · FastAPI · PostgreSQL 16 · Redis 7 · Ollama · Docker.

## Les six écrans

| # | Écran | Ce qu'on y fait |
|---|-------|-----------------|
| 1 | **Supervision** | KPI temps réel, MTTA/MTTR, respect des SLA, tendance 30 jours, menaces, canaux, incidents majeurs |
| 2 | **Signalements multicanal** | Déclaration web, saisie téléphonique, réception e-mail/SMS/WhatsApp (webhooks), formulaire public anonyme avec code de suivi ; tri : conversion en incident, rattachement, rejet |
| 3 | **Incidents** | Tickets `INC-AAAA-NNNN`, cycle de vie contrôlé, SLA, assignation, commentaires, chronologie, escalades L1→L2→L3→CERT, playbook, IOC liés |
| 4 | **Intelligence & IOC** | Indicateurs typés/normalisés (IP, domaine, URL, e-mail, hash, téléphone), TLP, import en masse, analyse de texte, veille OSINT, partage communautaire anonymisé |
| 5 | **Assistant IA** | Triage, génération de playbooks, questions — LLM local Ollama ou moteur de règles ; **validation humaine obligatoire** |
| 6 | **Rapports & administration** | Statistiques par période, rapport exécutif, exports, décisions sensibles, utilisateurs, journal d'audit vérifiable, rétention, jetons d'ingestion, organisations |

## Démarrage rapide (Docker)

```bash
cd ciip
cp .env.example .env          # puis remplacer les secrets (voir commentaires)
docker compose up --build
```

* Interface : <http://localhost:8080>
* Documentation interactive de l'API : <http://localhost:8080/api/docs>
* Portail public anonyme : <http://localhost:8080/signaler/bfs>

Au premier démarrage, le backend applique les migrations Alembic puis charge le
jeu de données fictif (`CIIP_SEED_DEMO=true`). Le service `ollama-pull`
télécharge le modèle (`llama3.2:3b` par défaut, ~2 Go) ; en attendant, ou sans
accès Internet, l'assistant utilise automatiquement son moteur de règles.

### Comptes de démonstration

Mot de passe commun : `DemoCiip2026!`

| Compte | Rôle | Pour tester |
|--------|------|-------------|
| `analyste@bfs.example` | Analyste | Tri, incidents, IOC, demandes de décision |
| `lead@bfs.example` | Analyste habilité | Approuver les décisions, valider l'IA, voir les PII |
| `admin@bfs.example` | Administrateur | Utilisateurs, audit, rétention, jetons |
| `declarant@bfs.example` | Déclarant | Déclarer et suivre ses propres signalements |
| `auditeur@bfs.example` | Auditeur | Lecture seule + journal d'audit |
| `analyste@mdn.example` | Analyste (autre organisation) | Vérifier l'isolation des données |
| `superadmin@ciip.example` | Opérateur plateforme | Créer des organisations |

### Scénario de démonstration (10 minutes)

1. **Public** — sur `/signaler/bfs`, envoyer un signalement anonyme ; noter le code `SIG-…`, le suivre sur `/suivi`.
2. **Analyste** — *Signalements* → ouvrir le signalement → *Créer l'incident*.
3. Dans l'incident : *Proposer un triage* (IA). La proposition reste **en attente**.
4. **Analyste habilité** — *Valider et appliquer* : catégorie, sévérité, SLA et playbook sont mis à jour et tracés.
5. Analyste : *Escalade externe (CERT national)…* → une **demande de décision** est créée.
6. Analyste habilité : *Rapports & admin → Décisions* → approuver (le demandeur ne peut pas s'auto-approuver).
7. **Administrateur** — *Journal d'audit* → *Vérifier l'intégrité* (chaîne SHA-256).
8. Se connecter avec `analyste@mdn.example` : aucun incident de la banque n'est visible.

### Webhooks de réception (e-mail / SMS / WhatsApp)

```bash
curl -X POST http://localhost:8080/api/v1/intake/sms/bfs \
  -H "X-Intake-Token: demo-intake-token-bfs" -H "Content-Type: application/json" \
  -d '{"sender": "+22500000042", "body": "On me demande mon code de retrait mobile money"}'
```

Le jeton de démonstration est fictif ; régénérez-le dans *Administration → Organisation*.

## Développement sans Docker

Prérequis : Python 3.12+, Node 22+, PostgreSQL 16, Redis 7 (facultatif), Ollama (facultatif).

```bash
# Backend
cd ciip/backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
export CIIP_DATABASE_URL=postgresql+psycopg://ciip:ciip@localhost:5432/ciip
alembic upgrade head && python -m app.seed
uvicorn app.main:app --reload --port 8000

# Frontend (autre terminal) — le serveur Vite relaie /api vers :8000
cd ciip/frontend
npm ci && npm run dev            # http://localhost:5173
```

Sans Redis (`CIIP_REDIS_URL=`), un stockage en mémoire est utilisé (un seul processus).
Sans Ollama (`CIIP_AI_USE_OLLAMA=false`), seul le moteur de règles est utilisé.

## Tests

```bash
cd ciip/backend && pytest                 # 68 tests (SQLite, sans Redis ni LLM)
CIIP_TEST_DATABASE_URL=postgresql+psycopg://ciip:ciip@localhost:5432/ciip_test pytest   # sur PostgreSQL
ruff check .

cd ciip/frontend && npm test && npm run typecheck && npm run build
```

Couverture fonctionnelle des tests backend : authentification (verrouillage,
révocation, rotation), RBAC, **isolation inter-organisations**, cycle de vie et
SLA, escalades, quatre yeux, portail public (anti-robot, limitation de débit,
suivi), webhooks, chiffrement/masquage/expurgation des PII, IOC
(détection, défangage, extraction, partage), assistant IA (règles, validation,
sortie Ollama simulée et contrôlée), audit (détection d'altération), rapports.

## Organisation du code

```
ciip/
├── docker-compose.yml        PostgreSQL, Redis, Ollama, API, interface
├── docs/ARCHITECTURE.md      architecture, sécurité, modèle de données, feuille de route
├── docs/API.md               référence des endpoints
├── backend/
│   ├── alembic/versions/     migrations
│   ├── app/core/             configuration, sécurité, RBAC, protection des données, Redis
│   ├── app/api/              routes REST (un module par domaine)
│   ├── app/services/         logique métier (incidents, IOC, IA, décisions, audit, stats)
│   ├── app/seed.py           jeu de données fictif
│   └── tests/
└── frontend/src/
    ├── pages/                les six écrans + connexion + portail public
    ├── components/           UI, graphiques SVG, mise en page
    └── lib/                  client API, authentification, libellés
```

## Mise en production — points à traiter

Ce dépôt est un démonstrateur V1. Avant toute exploitation réelle :

* générer `CIIP_JWT_SECRET` et `CIIP_DATA_ENCRYPTION_KEY` (l'application refuse de démarrer en `CIIP_ENV=production` avec le secret par défaut) et les stocker dans un coffre ;
* placer l'interface derrière TLS (HSTS est activé en production) ;
* faire valider le traitement des données personnelles par le DPO au regard de la loi nationale applicable ;
* ajouter MFA, SSO et la Row-Level Security PostgreSQL (voir la feuille de route) ;
* remplacer les flux OSINT fictifs par de vrais connecteurs (MISP, OpenCTI, bulletins du CERT national).

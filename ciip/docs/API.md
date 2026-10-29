# Référence de l'API REST — `/api/v1`

Documentation interactive complète (OpenAPI) : `/api/docs`.
Authentification : `Authorization: Bearer <access_token>` sauf mention contraire.
L'organisation est toujours déduite du jeton ; un objet d'une autre organisation renvoie `404`.

## Authentification
| Méthode | Chemin | Permission | Description |
|---|---|---|---|
| POST | `/auth/login` | public | E-mail + mot de passe → jetons (verrouillage après 5 échecs) |
| POST | `/auth/refresh` | public | Rotation : le jeton de rafraîchissement est à usage unique |
| POST | `/auth/logout` | connecté | Révoque les jetons (Redis) |
| GET | `/auth/me` | connecté | Profil, organisation, permissions |
| POST | `/auth/change-password` | connecté | Politique de mot de passe appliquée |

## Incidents
| Méthode | Chemin | Permission |
|---|---|---|
| GET | `/incidents?status=&severity=&category=&q=&open_only=&page=&size=` | `incident:read` |
| POST | `/incidents` | `incident:write` |
| GET / PATCH | `/incidents/{id}` | `incident:read` / `incident:write` |
| POST | `/incidents/{id}/status` | `incident:write` — clôture d'un critique → `409`, passer par une décision |
| POST | `/incidents/{id}/assign` | `incident:write` |
| POST | `/incidents/{id}/comments` | `incident:write` |
| POST | `/incidents/{id}/escalate` | `incident:escalate` — L1→L2→L3 ; `external` → décision |
| GET | `/incidents/{id}/escalations` | `incident:read` |
| GET | `/incidents/export.csv` | `reports:read` |

## Signalements
| Méthode | Chemin | Permission |
|---|---|---|
| POST | `/reports` | `report:submit` (déclarant : canal web uniquement) |
| GET | `/reports` | `report:submit` (déclarant : ses signalements) |
| GET | `/reports/{id}?reveal=true` | `pii:read` pour `reveal` (lecture tracée) |
| POST | `/reports/{id}/convert` | `report:triage` — nouvel incident ou `merge_into_incident_id` |
| POST | `/reports/{id}/reject` | `report:triage` |
| GET | `/public/organizations/{slug}` | public |
| POST | `/public/{slug}/reports` | public, limité à 20/h/IP, champ piège `website` |
| GET | `/public/reports/{code}` | public — statut uniquement |
| POST | `/intake/{email\|sms\|whatsapp}/{slug}` | en-tête `X-Intake-Token` |

## Intelligence
| Méthode | Chemin | Permission |
|---|---|---|
| GET | `/intel/iocs?type=&tlp=&q=&include_community=` | `intel:read` |
| POST | `/intel/iocs` | `intel:write` — type détecté, valeur normalisée, dédoublonnage |
| PATCH | `/intel/iocs/{id}` | `intel:write` |
| GET | `/intel/iocs/{id}/enrich` | `intel:read` — enrichissement hors ligne |
| POST / DELETE | `/intel/iocs/{id}/link/{incident_id}` | `intel:write` |
| POST | `/intel/iocs/import` | `intel:write` — extraction depuis un texte libre |
| GET | `/intel/iocs/export?fmt=csv\|json&include_red=` | `intel:read` — TLP:RED exclu par défaut |
| POST | `/intel/match` | `intel:read` — indicateurs d'un texte déjà connus |
| GET | `/intel/feed?tag=` · POST `/intel/feed/sync` | `intel:read` · `intel:write` |

## Assistant IA et playbooks
| Méthode | Chemin | Permission |
|---|---|---|
| GET | `/ai/status` | `ai:use` |
| POST | `/ai/triage` · `/ai/playbook` · `/ai/ask` | `ai:use` |
| GET | `/ai/suggestions?incident_id=&status=` | `ai:use` |
| POST | `/ai/suggestions/{id}/review` | `ai:validate` — applique la proposition si approuvée |
| GET | `/playbooks` · `/playbooks/{id}` | `incident:read` |
| POST | `/playbooks` · `/playbooks/{id}/archive` | `playbook:write` |

## Décisions sensibles (quatre yeux)
| Méthode | Chemin | Permission |
|---|---|---|
| GET | `/decisions/types` · `/decisions?status=` | `decision:request` |
| POST | `/decisions` | `decision:request` (`purge_data` : administrateur) |
| POST | `/decisions/{id}/review` | `decision:approve`, demandeur exclu |

Types : `close_critical_incident`, `external_escalation`, `share_ioc`, `purge_data`.

## Statistiques et rapports
| Méthode | Chemin | Permission |
|---|---|---|
| GET | `/analytics/dashboard` | `dashboard:read` (cache Redis 30 s) |
| GET | `/analytics/summary?date_from=&date_to=` | `reports:read` |
| GET | `/analytics/executive?date_from=&date_to=` | `reports:read` — Markdown |

## Administration
| Méthode | Chemin | Permission |
|---|---|---|
| GET / POST | `/admin/users` · PATCH `/admin/users/{id}` | `user:manage` |
| GET | `/admin/assignees` | `incident:read` |
| GET / PATCH | `/admin/organization` | `org:settings` |
| POST | `/admin/organization/intake-token` | `org:settings` — affiché une seule fois |
| GET | `/admin/audit?action=` · `/admin/audit/verify` | `audit:read` |
| GET / POST | `/admin/organizations` | `org:manage` (opérateur plateforme) |

"""Reference playbooks shipped with the platform (organisation_id = NULL)."""

from app.models import Category


def _s(phase: str, title: str, detail: str, approval: bool = False) -> dict:
    return {"phase": phase, "title": title, "detail": detail, "requires_approval": approval}


REFERENCE_PLAYBOOKS: dict[Category, dict] = {
    Category.PHISHING: {
        "name": "Réponse à une campagne d'hameçonnage",
        "description": "Courriels ou SMS frauduleux visant les collaborateurs ou les clients.",
        "steps": [
            _s("Détection", "Collecter les échantillons", "Récupérer le message original avec en-têtes (.eml) et les liens."),
            _s("Analyse", "Extraire les indicateurs", "Domaines, URL, adresses d'expédition, IP ; les enregistrer comme IOC."),
            _s("Confinement", "Bloquer les indicateurs", "Bloquer domaines/URL sur le proxy et la passerelle mail ; purger les messages des boîtes."),
            _s("Confinement", "Réinitialiser les comptes exposés", "Forcer le changement de mot de passe et révoquer les sessions des utilisateurs ayant cliqué."),
            _s("Communication", "Alerter les utilisateurs", "Message de sensibilisation interne ; avertissement clients si la marque est usurpée."),
            _s("Retour d'expérience", "Demande de retrait du site", "Signaler le site frauduleux à l'hébergeur / registraire.", True),
        ],
    },
    Category.RANSOMWARE: {
        "name": "Réponse à un rançongiciel",
        "description": "Chiffrement de systèmes avec demande de rançon.",
        "steps": [
            _s("Confinement", "Isoler les systèmes touchés", "Déconnecter du réseau (sans éteindre) les postes et serveurs chiffrés."),
            _s("Confinement", "Protéger les sauvegardes", "Vérifier l'intégrité et déconnecter les sauvegardes hors ligne."),
            _s("Analyse", "Identifier la souche et le vecteur", "Note de rançon, extension, IOC ; chercher le point d'entrée (RDP, VPN, phishing)."),
            _s("Gouvernance", "Activer la cellule de crise", "Direction, juridique, communication ; aucun paiement sans décision formelle.", True),
            _s("Notification", "Notifier les autorités", "CERT national et autorité de protection des données si données personnelles.", True),
            _s("Rétablissement", "Restaurer depuis des sauvegardes saines", "Reconstruire, durcir, réinitialiser tous les identifiants à privilèges."),
        ],
    },
    Category.MOBILE_MONEY_FRAUD: {
        "name": "Fraude au mobile money",
        "description": "Transferts frauduleux, SIM swap, faux agents, arnaques aux codes de retrait.",
        "steps": [
            _s("Détection", "Qualifier les transactions", "Identifiants de transaction, montants, numéros émetteurs/bénéficiaires."),
            _s("Confinement", "Geler les comptes bénéficiaires", "Demande de gel auprès de l'opérateur / de l'émetteur de monnaie électronique.", True),
            _s("Analyse", "Vérifier un SIM swap", "Historique de changement de SIM et d'appareil du client victime."),
            _s("Intelligence", "Enregistrer les numéros frauduleux", "Créer des IOC de type téléphone et les partager si TLP le permet."),
            _s("Notification", "Informer la cellule anti-fraude et le régulateur", "Selon les obligations de la banque centrale / régulateur télécom.", True),
            _s("Communication", "Accompagner la victime", "Dépôt de plainte, conseils de sécurisation du compte."),
        ],
    },
    Category.DDOS: {
        "name": "Réponse à un déni de service distribué",
        "description": "Saturation d'un service exposé.",
        "steps": [
            _s("Détection", "Caractériser l'attaque", "Volumétrie, protocoles, IP sources, service ciblé."),
            _s("Confinement", "Activer la protection anti-DDoS", "Filtrage chez le FAI / fournisseur de scrubbing, limitation de débit."),
            _s("Confinement", "Basculer les services critiques", "Plan de continuité : site de secours, CDN."),
            _s("Communication", "Informer clients et partenaires", "Message d'indisponibilité maîtrisé."),
            _s("Retour d'expérience", "Analyser après l'attaque", "Ajuster les seuils et le dimensionnement."),
        ],
    },
    Category.DATA_BREACH: {
        "name": "Violation de données personnelles",
        "description": "Exfiltration ou exposition de données personnelles ou sensibles.",
        "steps": [
            _s("Confinement", "Stopper la fuite", "Fermer l'accès exposé, révoquer les clés, isoler le système."),
            _s("Analyse", "Évaluer le périmètre", "Types de données, nombre de personnes concernées, période."),
            _s("Gouvernance", "Saisir le DPO / juridique", "Qualification au regard de la loi nationale de protection des données."),
            _s("Notification", "Notifier l'autorité de protection des données", "Dans les délais légaux applicables.", True),
            _s("Notification", "Informer les personnes concernées", "Si risque élevé pour leurs droits.", True),
            _s("Rétablissement", "Corriger et durcir", "Correctifs, chiffrement, revue des accès."),
        ],
    },
    Category.MALWARE: {
        "name": "Infection par logiciel malveillant",
        "description": "Poste ou serveur infecté.",
        "steps": [
            _s("Confinement", "Isoler la machine", "Quarantaine réseau via l'EDR."),
            _s("Analyse", "Collecter les artefacts", "Empreintes, processus, persistance, connexions sortantes."),
            _s("Intelligence", "Rechercher d'autres machines touchées", "Chasse sur les IOC dans le parc."),
            _s("Éradication", "Nettoyer ou réinstaller", "Réinstallation recommandée en cas de doute."),
            _s("Rétablissement", "Réinitialiser les identifiants", "Comptes utilisés sur la machine."),
        ],
    },
    Category.ACCOUNT_COMPROMISE: {
        "name": "Compromission de compte",
        "description": "Prise de contrôle d'un compte utilisateur ou de service.",
        "steps": [
            _s("Confinement", "Suspendre les sessions", "Révoquer les sessions et jetons, réinitialiser le mot de passe."),
            _s("Analyse", "Revoir l'activité du compte", "Connexions, règles de transfert de messagerie, accès aux données."),
            _s("Rétablissement", "Activer la MFA", "Imposer l'authentification multifacteur."),
            _s("Retour d'expérience", "Sensibiliser l'utilisateur", "Origine probable de la compromission."),
        ],
    },
    Category.UNAUTHORIZED_ACCESS: {
        "name": "Accès non autorisé / intrusion",
        "description": "Accès illégitime à un système ou réseau.",
        "steps": [
            _s("Confinement", "Bloquer l'accès", "Fermer le vecteur (VPN, RDP, compte), bloquer les IP."),
            _s("Analyse", "Établir la chronologie", "Journaux d'authentification, mouvements latéraux."),
            _s("Éradication", "Supprimer les persistances", "Comptes créés, tâches planifiées, webshells."),
            _s("Notification", "Escalader selon l'impact", "CERT national si infrastructure critique.", True),
        ],
    },
    Category.DEFACEMENT: {
        "name": "Défiguration de site web",
        "description": "Modification non autorisée d'un site public.",
        "steps": [
            _s("Confinement", "Mettre le site en maintenance", "Page statique de remplacement."),
            _s("Analyse", "Conserver les preuves", "Captures, journaux du serveur web, fichiers modifiés."),
            _s("Éradication", "Corriger la vulnérabilité", "CMS, extensions, identifiants d'administration."),
            _s("Rétablissement", "Restaurer depuis une version saine", "Puis surveillance renforcée."),
        ],
    },
    Category.SOCIAL_ENGINEERING: {
        "name": "Ingénierie sociale / fraude au président",
        "description": "Manipulation d'un collaborateur pour obtenir un virement ou des informations.",
        "steps": [
            _s("Confinement", "Bloquer le virement", "Contacter immédiatement la banque pour rappel de fonds.", True),
            _s("Analyse", "Reconstituer l'échange", "Courriels, appels, numéros utilisés."),
            _s("Intelligence", "Enregistrer les indicateurs", "Adresses e-mail, numéros, domaines sosies."),
            _s("Communication", "Sensibiliser les services exposés", "Finance, RH, assistants de direction."),
        ],
    },
    Category.OTHER: {
        "name": "Réponse générique à incident",
        "description": "Cadre NIST SP 800-61 pour les incidents non catégorisés.",
        "steps": [
            _s("Détection", "Qualifier l'incident", "Périmètre, impact, criticité."),
            _s("Confinement", "Limiter l'impact", "Mesures conservatoires proportionnées."),
            _s("Éradication", "Traiter la cause", "Correction de la cause racine."),
            _s("Rétablissement", "Revenir à la normale", "Surveillance renforcée."),
            _s("Retour d'expérience", "Capitaliser", "Mettre à jour les procédures."),
        ],
    },
}

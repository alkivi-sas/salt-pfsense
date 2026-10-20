# Journal de bord

Une entrée par séance de travail : date, lot et tâche, verrous concernés, ce qui a été fait, résultat, PR.

## 2026-10-12 → 2026-10-13 — Cadrage

- **Analyse de l'existant :** usage de FauxAPI (5 actions), mécanismes d'application par module, bugs latents, absence de tests.
- **Étude de pfrest v2 :**
  - versions et compatibilité ;
  - authentification et privilèges ;
  - catalogue d'endpoints ;
  - sémantique des identifiants et de l'application ;
  - cycle de vie du paquet.
- **Verrous :** formulation des verrous V1 à V8.
- **Résultat :** plan de migration.

## 2026-10-19 — Plan versionné

- **PR #8 :** plan de migration versionné dans `docs/migration/plan.md`.

## 2026-10-19 — Lot 0 : état des lieux

- **T0.5 :** initialisation de `docs/rd/` et état de l'art.
- **T0.1 :** 206 pare-feux relevés.
  - 146 sont compatibles pfrest v2.10.2, 1 v2.7.7 et 5 v2.4.3.
  - 48 n'ont aucune version v2 : CE 2.4.4 à 2.7.0.
  - 6 sont en armv7, non supporté.
  - Le paquet v2.10.2 déclare une ABI indépendante de l'architecture (`FreeBSD:15:*`) ; le fonctionnement sur arm64 reste à valider.
  - Proposition : une seule version épinglée, v2.10.2 (V6).
- **T0.2 :** usage des modules relevé dans le dépôt de states. Les plus utilisés sont alias, syslog, filter_rule et user.
  - Incohérence trouvée : le chemin du helper des boot environments est faux.
- **T0.3 :** déploiement des helpers et de FauxAPI documenté.
  - FauxAPI 1.4_1 exige un correctif local sur les versions récentes.
- **T0.4 :** couverture pfrest relevée sur v2.10.2, v2.7.7 et v2.4.3.
  - `dry_run` uniquement en v2.10.2 ; export OpenVPN absent en v2.4.3.
  - JSON Kea personnalisé non exposé dans aucune version (V4, V8).
- **T0.6 :** en attente, la lecture de la configuration DHCP du parc n'est pas autorisée dans la session.

## 2026-10-19 — Lot 0 : périmètre et inventaire DHCP

- **Périmètre :** seules les versions de pfSense sur FreeBSD 14, 15 ou 16 sont retenues.
  - 159 pare-feux sont dans le périmètre et 47 en sortent.
  - Une seule version pfrest est épinglée, v2.10.2 (V6).
- **T0.6 :** lecture autorisée, puis relevé DHCP de 204 pare-feux sur 206 (2 hors ligne).
  - 121 sont déjà sous Kea, 14 sont migrables automatiquement.
  - 3 nécessitent l'option 66 et 9 ont un failover ISC à migrer à la main.
  - Conséquence pour V8 : la table de traduction doit être étendue à l'option 66, à valider par capture en lab.

## 2026-10-20 — Lot 1 : socle qualité, oracle, corrections

- **T1.1 :** environnement de développement reproductible.
  - pipenv, Python 3.13, Salt 3008.2 comme sur les pare-feux.
  - black, flake8 et mypy ; pre-commit sur le code nouveau.
  - Chargeur de modules Salt avec dunders injectés, et faux client FauxAPI en mémoire.
- **T1.2 :** intégration continue (pre-commit + pytest) sur chaque PR.
- **T1.5 :** oracle `config.xml` (V5).
  - Parse, retrait des champs volatils, diff par chemin en conservant l'ordre des listes.
  - Registre des écarts acceptés.
- **T1.7 :** correction de 9 défauts, chacun avec un test qui échoue avant la correction et passe après.
  - Chemin du helper des boot environments, journalisation SSH, message WireGuard.
  - Création du premier VLAN et mode test VLAN.
  - Idempotence et mode test du cron, comparaison int/str.
  - `need_changes` des interfaces.
  - `absent` des règles de filtrage.
  - Export OpenVPN du premier certificat.
  - Création de certificat utilisateur en Python 3.
  - Deux défauts suspectés à l'inventaire se sont révélés sans effet après lecture : l'index du cron et la variable `certid` de l'export. Ils ne sont pas modifiés.
- **T1.8 :** 9 tests unitaires de la traduction ISC → Kea (EXP-08).
  - Protocole de capture DHCP rédigé.
  - Incertitude nouvelle : Kea refuse probablement la redéfinition d'options standard (option 66), ce qui pourrait exiger un traitement distinct dans la table.
- **T1.3, T1.4, T1.6 :** lab spécifié.
  - 9 scénarios de référence et leur runner livrés.
  - Exécution, fixtures réelles et captures en attente du lab.

## 2026-10-20 — Décision : pas de lab

- Le lab est abandonné à ce stade : les lots suivants sont développés et testés sans pare-feu de test.
- Conséquence pour le dossier R&D : les critères de levée des verrous qui exigent des mesures (V1 à V8) restent « en cours ». Ils seront mesurés au déploiement pilote, ou sur un lab ultérieur.

## 2026-10-20 — Lot 2 : client pfrest et abstraction de backend

- **Contrat v2.10.2.** Il est extrait du schéma OpenAPI publié (95 endpoints, 57 modèles) et versionné dans `pfrest/contract/`.
  - Un faux serveur pfrest en mémoire valide chaque requête contre ce contrat : champ inconnu, champ en lecture seule ou champ requis manquant donnent une erreur 400.
  - Il reproduit les identifiants positionnels.
  - Premier outil de V6 : les tests de contrat.
- **Client** (V1, V2, V3) :
  - résolution d'identité par clé métier et vérification après écriture ;
  - verrou de run et détection des écritures tierces par l'historique de configuration ;
  - `dry_run` sur toutes les écritures ;
  - application synchrone par domaine.
- **Backend.** Le choix se fait par module via le pillar ; FauxAPI reste le défaut.
- **Lecture de configuration.** Elle se fait en local par le parseur de pfSense (PHP), au même format que FauxAPI.
- **Architecture retenue pour le lot 4.** Le code pfrest de chaque module va dans un util typé (`_utils/pfrest_<domaine>.py`). Les modules existants n'aiguillent que selon le backend.

## 2026-10-20 — Lot 3 : cycle de vie du paquet pfrest

- **Version épinglée v2.10.2.** Les bases supportées sont relevées sur les assets de la release.
  - Installation par asset figé ; sur Plus, contournement des dépôts Netgate (`-C /dev/null`).
  - Changement de version par `pfsense-restapi revert <tag>`, jamais `latest`.
- **V7, amorçage sans secret humain.** Implémenté.
  - La clé est générée hors du pare-feu et stockée dans le pillar chiffré.
  - Le pare-feu ne reçoit que son hash (`sha256`), écrit par un helper local avec l'utilisateur et le groupe dédiés ; `KeyAuth` est activé.
  - Aucun mot de passe administrateur n'est manipulé.
  - Tests : la clé n'apparaît ni dans la requête au helper, ni dans les changements ; le fichier de clé est en 0600.
- **Moindre privilège.** La liste des privilèges est dérivée des endpoints réellement utilisés, et chaque couple endpoint/méthode est vérifié contre le contrat. `command_prompt` et `page-all` sont exclus.
- **Constat tiré du contrat.** `represent_interfaces_as` vaut `descr` par défaut : l'API exposerait les noms affichés des interfaces. Il est forcé à `id` pour conserver les identifiants internes utilisés par les modules.
- **Non vérifié sans lab :**
  - effet de l'access list ;
  - restauration de `backup.json` après une mise à jour de pfSense ;
  - appels `local_user_set` et `local_group_set` en ligne de commande.

## 2026-10-20 — Lot 4 : migration des modules

- **Socle.** Chaque module garde ses fonctions publiques et aiguille vers un util typé `_utils/pfrest_<domaine>.py`.
  - Chaque écriture se fait dans une session verrouillée (V2).
  - L'apply est immédiat par défaut, comme avec FauxAPI. Il peut être différé par pillar avec le state `pfsense_apply` (V3).
  - La synchronisation HA a lieu après les écritures, là où FauxAPI la faisait.
- **Modules migrés :** alias, syslog, règles de filtrage, NAT, utilisateurs et groupes, clés SSH, cron, VLAN, static mappings DHCP, serveurs DNS, interfaces et passerelles, certificats et CRL, OpenVPN (lecture et export), pairs WireGuard.
- **Constats et choix (V5, équivalence sémantique) :**
  - **Lectures.** Elles restent sur `config.xml` partout où pfrest masque des secrets (hash, clés privées, PSK) ou ne modélise pas un champ (identifiant cron, passerelles DNS) : les formes renvoyées restent exactement celles de FauxAPI.
  - **Mots de passe.** Le pillar porte des hashes bcrypt, que pfrest ne peut pas recevoir. Ils passent par un helper local sur liste blanche.
  - **Règles et NAT.** Une conversion bidirectionnelle conserve les objets et la clé métier existants :
    - `wanip` devient `wan:ip`, la négation `!` est conservée ;
    - les plages `-` deviennent `:` ;
    - l'interface passe en liste.
  - **Contrat.** Les champs requis du schéma OpenAPI sont parfois conditionnels (interfaces, PKI). Le faux serveur en tient compte.
- **Défauts trouvés et corrigés en route :**
  - `sourceip` vide non idempotent (syslog) ;
  - mot de passe réécrit à chaque passage (user) ;
  - VLAN réécrit à chaque passage.
- **Reportés au lot 5 :** `webgui_settings` et `dhcp_kea`, qui dépendent de champs non modélisés (helper générique).

## 2026-10-20 — Lot 5 : manques fonctionnels

- **Helper générique `config_path.php`** (V4). Il lit, écrit ou supprime un chemin de `config.xml` sur liste blanche (8 motifs), puis lance des actions d'application elles aussi sur liste blanche.
  - Les helpers PHP sont désormais testés contre des stubs pfSense : `config_path`, amorçage de l'API, champs utilisateur.
  - Ces tests ont confirmé l'idempotence de l'amorçage.
- **Modules couverts par ce helper :** althostname, sshguard (même application que l'ancien helper), PPPoE noyau, sudo, agent zabbix, clés WebGUI non modélisées, passerelles par serveur DNS, `numberofitems` du syslog.
- **Migration Kea** (V8) :
  - même traduction, JSON Kea par le helper ;
  - backend basculé en dernier par l'API, puis un seul apply DHCP ;
  - tout autre écart en attente est refusé.
- **EXP-04.** Conclue par analyse du code du paquet : les endpoints ajoutés seraient effacés à chaque réinstallation, donc le helper générique est retenu.
- **Restent non couverts, avec refus explicite :** alias URL table et champs avancés des règles. Les boot environments restent sur leur helper dédié.

## 2026-10-20 — Lot 6 : recettes de déploiement Salt

- **33 recettes au même format** (9 sections) : 8 socle, 19 par domaine, 6 d’exploitation.
- **Exemples réels** dans `examples/` : un pillar et 22 SLS.
- **Validation hors ligne**, à défaut de lab (T6.5) :
  - structure des recettes et existence des fichiers cités ;
  - rendu Jinja/YAML de chaque SLS ;
  - existence de chaque fonction de state ou de module appelée.

## 2026-10-20 — Lot 7 : plan de déploiement

- **Plan exécutable** (`docs/migration/rollout.md`), non exécuté faute de fenêtre et de lab :
  - un pilote à exposition minimale ;
  - trois vagues (37 amd64, 100 arm64, 4 paires HA) ;
  - les cas armv7 (6) et les mises à jour pfSense préalables (7) ;
  - la migration Kea en trois étapes ;
  - les critères de passage et les indicateurs.
- **Défaut corrigé en préparation :** le state interface réécrivait chaque passage, ce qui aurait déclenché un apply à chaque run sur pfrest.

## 2026-10-20 — Lot 8 : capitalisation

- **Nettoyage.** Suppression des helpers jamais appelés.
  - Le backend FauxAPI est conservé, gelé, pour les 47 pare-feux hors périmètre.
  - La désinstallation de FauxAPI est encadrée par un garde-fou : la recette 46 ne s'applique que si le pare-feu et tous ses modules sont sur pfrest.
- **README et CHANGELOG** du dépôt.
- **EXP-01** (V1) sur banc logiciel : 0 écriture sur un mauvais objet sur 1 000 opérations aléatoires avec résolution par clé métier, contre 105 sur 200 avec un identifiant mis en cache.
- **Synthèse.** Statuts des verrous mis à jour ; résultats, contribution et synthèse rédigés. Les mesures de terrain restent à faire au pilote.

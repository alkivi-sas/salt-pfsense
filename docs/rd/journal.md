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

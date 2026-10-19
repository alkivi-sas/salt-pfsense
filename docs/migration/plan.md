# Migration d'une couche de gestion déclarative pfSense : de FauxAPI vers pfSense REST API v2

## Contexte

Le projet `salt-pfsense` regroupe des extensions SaltStack pour pfSense. Il pilote de façon déclarative la configuration d'un parc de pare-feux (filtrage, NAT, alias, utilisateurs, PKI, VPN, DHCP, VLAN, DNS, journalisation, cron, etc.). Volume actuel : ≈ 9 700 lignes, dont 23 modules d'exécution (`_modules/`), 16 states (`_states/`), 1 grain (`_grains/pfsense.py`), 1 client HTTP (`_utils/pfsense.py`) et ≈ 1 650 lignes de helpers PHP (`helpers*/`). Le projet n'a ni test, ni outillage qualité, ni documentation.

### Couche d'accès actuelle

Toute la couche d'accès repose sur **FauxAPI**. Ce projet est archivé depuis le 2026-06-07 ; sa dernière release date de 2020 et n'a été testée que jusqu'à pfSense 2.4.5. Le code n'en utilise que 5 actions :
- `config_get` ;
- `config_set`, qui réécrit `config.xml` en entier ;
- `config_patch`, qui réécrit une section entière ;
- `send_event` (`filter reload`, `interface reconfigure`) ;
- `function_call` (`interface_bring_down`, `system_syslogd_start`, `filter_pflog_start`).

### Défauts mesurés

- **Écritures massives et concurrentes.** Une même fonction fait 3 à 6 `config_get` complets. Toute écriture remplace une section entière, voire la config entière.
- **Application incohérente.** Le reload est déclenché par `send_event`, par des helpers PHP, par des scripts `rc.*`, par un `atexit`… ou pas du tout (cron, VLAN, SSH, WebGUI, sudo, zabbix).
- **Synchronisation HA partielle.** `_sync_ha` n'est appelé que dans 5 modules.
- **States défaillants :**
  - test mode cassé : `cron` (update), `interface`, `vlan`, `user_cert` ;
  - `filter_rule.absent` plante ;
  - `filter_rule` et `nat_rule` ne savent pas mettre à jour une règle existante ;
  - `user.present` avec mot de passe n'est jamais idempotent.

### Chantier lié : migration DHCP ISC → Kea

ISC DHCP est en fin de vie et pfSense passe progressivement à Kea.

Les PR #6 et #7 (mergées, encore sur FauxAPI) ajoutent `_modules/pfsense_dhcp_kea.py` et `_states/pfsense_dhcp_kea.py`. Ce code :
- convertit les options DHCP ISC personnalisées (`dhcpd.<if>.numberoptions`) en configuration Kea, d'après une table déclarée dans le pillar `pfsense:dhcp_kea:options` (code → nom, type, `format: hex`, `always-send`). Exemples :
  - option 43 « contrôleur Wi-Fi », type binaire, en hexadécimal ;
  - option 132 « VLAN téléphonie », type chaîne, avec `always-send` ;
- écrit une `option-def` globale (`kea.custom_kea_config`) et une `option-data` par interface (`dhcpd.<if>.custom_kea_config`), en JSON encodé base64 ;
- vide les `numberoptions` et bascule `dhcpbackend` sur `kea` ;
- applique par `function_call(services_dhcpd_configure)` puis `rc.filter_synchronize` ;
- refuse la migration en cas de failover DHCP, d'option absente de la table ou de configuration Kea divergente ;
- ne fait rien sur un pare-feu sans DHCP.

Il n'a été validé qu'en simulation (FauxAPI mockée), sans test sur un vrai pare-feu, et reproduit une migration faite à la main sur deux pare-feux pilotes.

La migration Kea entre dans le projet : même socle de tests, même bascule vers pfrest, mêmes recettes, même déploiement progressif.

### Cible

**pfSense-pkg-RESTAPI v2** (« pfrest », v2.10.2 du 2026-08-23). Elle apporte :
- des modèles typés et validés ;
- un `dry_run` natif ;
- des privilèges par endpoint et par méthode HTTP ;
- un verrou d'écriture serveur ;
- des endpoints `apply` par domaine.

### Résultat attendu

- **Contrat inchangé :** même interface Salt, avec des signatures publiques stables.
- **Idempotence et test mode fiables.**
- **Tests automatisés.**
- **Bascule progressive et réversible**, pare-feu par pare-feu.
- **Recettes de déploiement documentées et testées.**

---

## Verrous techniques et incertitudes (volet R&D)

Les points ci-dessous ont une issue inconnue a priori. Chacun reçoit une hypothèse, un protocole d'expérimentation et un critère de validation. Les PR y font référence (`V1` à `V8`).

| # | Verrou | Hypothèse de départ | Expérimentation | Critère de levée |
|---|---|---|---|---|
| **V1** | **Identifiants volatils.** pfrest identifie un objet par son index dans `config.xml`, et cet index change à chaque suppression ou insertion. Or un moteur déclaratif exige une identité stable. | Une clé métier par type d'objet, plus un cycle « relire → résoudre → écrire → revérifier », suffit. | Scénarios de suppressions et insertions intercalées sur le lab ; injection d'écritures concurrentes pendant un run. | 0 écriture sur le mauvais objet sur 1 000 itérations aléatoires. |
| **V2** | **Concurrence sur `config.xml`.** Le verrou serveur pfrest ne couvre qu'une requête, pas une séquence lecture → écriture. La WebGUI, la synchro HA et un autre run peuvent s'intercaler. | Verrou fichier côté minion + détection de conflit via `diagnostics/config_history`. | Runs Salt parallèles et modifications WebGUI simultanées. | Conflit détecté et run en échec propre, jamais d'écrasement silencieux. |
| **V3** | **Écriture et application séparées.** `apply=false` par défaut met le changement en attente. Certains modèles sont `always_apply`. `FirewallRule` n'a pas de subsystem, donc `GET /firewall/apply` peut répondre « applied » à tort. | Un state `apply` par domaine, déclenché par `onchanges`, réduit le nombre de reloads sans perdre de cohérence. | Mesure du nombre de reloads pf et de la durée de run, avant et après. | Au plus 1 reload par domaine et par run ; état appliqué vérifié par lecture pf. |
| **V4** | **Couverture incomplète.** Aucun endpoint pour : PPPoE kernel, althostnames, sshguard, boot environments, paquets sudo et zabbix-agent, passerelles par serveur DNS (`dnsNgw`), restauration de config. Endpoints partiels pour WebGUI et SSH. | Un helper PHP générique `config_get_path`/`config_set_path` couvre les manques plus durablement qu'un endpoint custom, car les endpoints custom sont effacés à chaque mise à jour du paquet. | Prototype des deux options ; cycle mise à jour du paquet → highstate. | Option retenue survit à 3 cycles d'upgrade sans intervention manuelle. |
| **V5** | **Équivalence sémantique.** pfrest injecte des valeurs par défaut (`tracker` horodaté en lecture seule, `created_by`, `detail` d'alias, `icmptype`) et change des formats (`interface` en liste pour les règles, `source` en chaîne, `authorizedkeys` en clair, `password` en clair haché côté serveur). | Un diff normalisé de `config.xml` avec une liste d'exclusions explicite suffit comme oracle. | Rejouer chaque scénario sur les deux backends. | Écarts restants = 0 hors registre documenté. |
| **V6** | **Hétérogénéité des versions.** pfrest v2.10.x ne couvre que CE 2.8.1/2.9.0 et Plus 25.11.1+ ; v2.7.7 couvre CE 2.8.0 et Plus 24.11–26.03 ; v2.4.3 couvre CE 2.7.2 et Plus 24.03. CE 2.7.0/2.7.1 et Plus 23.09 n'ont aucun pfrest v2. L'API change entre mineures (2.5, 2.7, 2.9, 2.10). Périmètre retenu : pfSense sur FreeBSD 14, 15 ou 16 uniquement (voir `versions.md`). | Une seule version pfrest épinglée (v2.10.2) pour tout le périmètre, après mise à jour des quelques pare-feux sur des versions non couvertes. Les montées de version de pfrest passent par une suite de contrat. | Lab sur chaque base (CE 2.8.1, CE 2.9.0, Plus 26.07) et chaque architecture (amd64, arm64, armv7) ; tests de contrat sur le schéma OpenAPI de la version épinglée et de la suivante. | Suite de tests verte sur chaque base et architecture du périmètre. |
| **V7** | **Bootstrap sans secret humain.** La première clé API exige normalement une auth Basic avec un compte admin. Or pfrest ne stocke que le hash de la clé dans `config.xml`. | Salt peut générer la clé, en écrire le hash et créer l'utilisateur dédié par helper local, sans jamais manipuler le mot de passe admin. | Bootstrap sur lab vierge, puis vérification de l'auth `X-API-Key` et des privilèges. | Bootstrap idempotent, clé jamais visible dans les logs ni dans `changes`. |
| **V8** | **Traduction sémantique ISC → Kea.** Les deux serveurs n'ont pas le même modèle d'options : ISC a des `numberoptions` typées par interface ; Kea demande une `option-def` globale typée plus une `option-data` par sous-réseau, avec des encodages différents (binaire en hexadécimal, chaîne, `always-send`). Le failover ISC n'a pas d'équivalent direct (Kea HA). pfrest expose le choix du backend (`services/dhcp_server/backend`) et les static mappings communs, mais probablement pas le JSON Kea personnalisé (à vérifier sur l'OpenAPI). | Une table de traduction fermée, déclarée en pillar (options connues seulement, refus explicite sinon), donne un service DHCP identique vu du client. | Captures DHCP (`tcpdump -vv port 67`) avant et après migration sur le lab : offres comparées option par option, pour un client Wi-Fi et un téléphone IP. | Offres DHCP identiques (options, valeurs, bail) sur 100 % des scénarios ; 0 migration silencieuse d'une configuration non gérée. |

---

## Principes d'architecture

1. **Contrat public inchangé.** Les signatures publiques des fonctions `pfsense_*.*` appelées par les states ne changent pas. On ne fait que des ajouts : un state `apply` par domaine et des paramètres optionnels.
2. **Deux backends derrière un sélecteur.** On ajoute `_utils/pfrest.py` à côté de `FauxapiLib`, et le choix se lit dans le pillar `pfsense:api_backend` (`fauxapi` par défaut, ou `pfrest`), avec possibilité de surcharge par module (`pfsense:api_backend_overrides:<module>`). On peut ainsi basculer module par module et pare-feu par pare-feu, avec un retour arrière immédiat.
3. **Appels locaux uniquement.** Le minion tourne sur le pare-feu et appelle `https://127.0.0.1:<port webgui>/api/v2/`, authentifié par l'en-tête `X-API-Key`. La clé est liée à un utilisateur technique dédié qui n'a que les privilèges `api-v2-*-<méthode>` nécessaires : jamais `page-all`, jamais `api-v2-diagnostics-command-prompt-post`.
4. **Écritures par objet.** On passe par l'endpoint au singulier, avec POST, PATCH et DELETE. Le PUT au pluriel est interdit : il est destructif et sans `apply`.
5. **Application explicite et regroupée.** Chaque écriture se fait avec `apply=false`, puis un state `pfsense_apply.<domaine>` déclenché par `onchanges` lance `POST …/apply` avec `async=false`.
6. **Test mode Salt réel.** `test=True` envoie `dry_run=true` à pfrest : la validation serveur se fait, sans rien écrire.
7. **Secrets.** Clé API, mots de passe et PSK : jamais dans les logs, jamais dans `changes`, jamais dans les messages d'exception. On les masque avec une fonction `redact()`, en réutilisant les motifs de `_modules/pfsense_config.py` (`SENSITIVE_KEYS`/`SENSITIVE_PATTERNS`).

---

## Lots de travail

Pour chaque tâche : objectif, actions, livrable, critère de fin et commits prévus. Les messages de commit sont en anglais au format `type(scope): message`, comme dans l'historique du dépôt. Chaque lot fait l'objet d'une branche et d'une PR dédiée, avec au moins un commit par tâche (voir « Enchaînement des lots »).

### Lot 0 — État des lieux et cadrage (≈ 4 j/h)

**T0.1 Matrice de versions du parc**
- Actions :
  - Collecter les grains `version`, `platform` et `netgate_model` de tous les minions pfSense.
  - Croiser avec la matrice de compatibilité pfrest :
    - CE 2.8.1/2.9.0 et Plus 25.11.1+ → v2.10.x ;
    - CE 2.8.0 et Plus 24.11–25.11 → v2.7.7 ;
    - CE 2.7.2 et Plus 24.03 → v2.4.3 ;
    - au-delà → upgrade pfSense préalable.
- Livrable : `docs/migration/versions.md`, qui classe chaque pare-feu dans une colonne cible.
- Critère de fin : 100 % du parc classé.
- Décision prise : seules les versions sur FreeBSD 14, 15 ou 16 sont supportées (CE 2.7+, Plus 23.01+) ; les autres restent sur la couche actuelle, sans backend pfrest v1. Résultat dans `versions.md` : 159 pare-feux dans le périmètre, 47 hors périmètre.

**T0.2 Inventaire d'usage**
- Actions :
  - Recenser les sls et pillars externes qui appellent les states et modules `pfsense_*`.
  - Compter les appels par fonction.
  - Confirmer le code mort : `config_backup`/`config_restore`, `crl_unrevoke.php`, `nat_rule.php`, `pkg_manager.php`, `resolvconf.php`, `pfsense_user_cert.revoked`.
- Livrable : `docs/migration/usage.md`, qui donne la priorité de migration de chaque module.

**T0.3 Déploiement actuel des helpers**
- Actions :
  - Retrouver le sls externe qui copie `helpers/` et `helpers-<version>/` vers `/opt/helpers` et `/scripts`.
  - Retrouver son mapping de version : `23XXRELEASE` ne peut pas venir directement du grain `version`.
- Livrable : section « existant » de `docs/migration/helpers.md`.

**T0.4 Matrice de couverture**
- Actions :
  - Récupérer `openapi.json` de chaque version pfrest épinglée.
  - Pour chaque fonction publique, définir : endpoint, clé métier, champs, apply, écarts.
- Livrable : `docs/migration/coverage.md`, dont le tableau du lot 4 est la synthèse.

**T0.5 État de l'art et journal de bord R&D**
- Actions :
  - Recenser les solutions existantes : FauxAPI, pfrest v1/v2, collection Ansible pfrest, édition directe de `config.xml`.
  - Expliquer pourquoi aucune ne répond au besoin déclaratif Salt sans développement.
  - Ouvrir un journal de bord daté.
- Livrable : `docs/rd/` initialisé (structure décrite dans la section « Documentation R&D »).

**T0.6 Inventaire DHCP**
- Actions : pour chaque pare-feu, relever :
  - le backend (`dhcpbackend`) ;
  - les interfaces DHCP actives ;
  - les `numberoptions` par numéro d'option ;
  - la présence de failover (`failover_peerip`) ;
  - le nombre de static mappings ;
  - la présence de JSON Kea personnalisé.
- Livrable : `docs/migration/dhcp.md`, qui classe chaque pare-feu en :
  - « migrable automatiquement » (seulement des options présentes dans `pfsense:dhcp_kea:options`) ;
  - « option à ajouter à la table » ;
  - « manuel » (failover).
- Critère de fin : chaque pare-feu classé ; liste des options hors table, à ajouter au pillar `pfsense:dhcp_kea:options` après validation.

Commits :
- `docs(migration): add pfSense version matrix and pfrest targets`
- `docs(migration): inventory module usage and dead code`
- `docs(migration): document helpers deployment`
- `docs(migration): pfrest coverage matrix`
- `docs(rd): state of the art and research log`

### Lot 1 — Socle qualité, banc de test et oracle (≈ 9 j/h)

**T1.1 Outillage**
- Actions :
  - Ajouter `pyproject.toml` : black et flake8 à 120 colonnes, mypy, pytest.
  - Ajouter `.pre-commit-config.yaml` et `requirements-dev.txt`.
  - Ajouter `tests/conftest.py`, qui charge les modules Salt avec des dunders mockés (`__salt__`, `__context__`, `__pillar__`, `__grains__`, `__opts__`).
  - Ne pas reformater l'existant en masse : black ne s'applique qu'aux fichiers touchés.
- Critère de fin : `pre-commit run --all-files` et `pytest` passent en CI.
- Commits :
  - `chore(tooling): add pyproject, pre-commit and dev requirements`
  - `test: add salt loader fixtures`

**T1.2 CI**
- Actions : workflow GitHub Actions avec pre-commit et pytest unitaire, en Python 3.12 (FreeBSD py-salt) et 3.14 (onedir 3008).
- Commit : `ci: run pre-commit and unit tests`

**T1.3 Lab**
- Actions :
  - Monter des VM pfSense CE 2.8.1, CE 2.9.0 et Plus 26.07 (amd64), plus un boîtier arm64 et un boîtier armv7 en Plus 26.07. Ces bases et architectures sont celles du périmètre (`versions.md`).
  - Installer sur chacune un minion Salt, FauxAPI et pfrest côte à côte.
  - Prévoir des snapshots nommés `clean`, `fauxapi`, `pfrest`.
  - Écrire un script `tests/lab/reset.sh` qui restaure un snapshot.
- Livrable : `docs/migration/lab.md` (installation reproductible).
- Commit : `test(lab): document and script the pfSense lab`

**T1.4 Fixtures enregistrées**
- Actions :
  - Enregistrer les réponses réelles FauxAPI et pfrest du lab dans `tests/fixtures/<backend>/<endpoint>.json`.
  - Masquer les secrets avant tout commit.
- Commit : `test: record fauxapi and pfrest fixtures`

**T1.5 Oracle `config.xml`**
- Actions : écrire `tests/oracle/diff_config.py`, qui :
  1. parse deux `config.xml` ;
  2. normalise l'ordre des clés, les booléens (`''` ou absent), base64 ou clair ;
  3. exclut `revision`, `tracker`, `created*`, `updated*`, `detail` auto ;
  4. produit un diff lisible ;
  5. confronte chaque écart restant au registre `tests/oracle/accepted_diffs.yaml`.
- Commits :
  - `test(oracle): config.xml normalized diff`
  - `test(oracle): accepted differences registry`

**T1.6 Scénarios de référence**
- Actions : pour chaque state, écrire un sls de scénario dans `tests/lab/scenarios/<module>/`, avec 6 étapes : création, idempotence (2e run = 0 changement), modification, `test=True`, suppression, idempotence de la suppression.
- Critère de fin : les scénarios tournent sur le backend FauxAPI actuel. Les échecs connus sont marqués `xfail` avec le bug référencé ; c'est la ligne de base.
- Commits : un par domaine, par exemple `test(lab): alias scenarios`.

**T1.7 Corrections préalables**
- Actions : corriger les bugs qui bloquent les scénarios, chacun avec un test qui échoue avant et passe après :
  - `pfsense_interface.need_changes` ;
  - `pfsense_vlan` (`vlan` indéfini et cas `vlans == ''`) ;
  - `pfsense_cron` (décalage d'index, `wanted_data`) ;
  - `pfsense_filter_rule.absent` ;
  - `pfsense_user.export_openvpn_config` (index 0, `certid`) ;
  - `pfsense_ssh` (`log`) ;
  - `pfsense_wireguard` (`peeer_name`) ;
  - `pfsense_certificate` (`raise None`, `keys()[0]`, `id_type`, tuple de `get_user`).
- Commits : un `fix(<module>): …` par bug.

**T1.8 Valider la migration Kea (PR #6 et #7 mergées)**
- Actions :
  1. Ajouter les tests unitaires de `pfsense_dhcp_kea`, à partir de la simulation déjà faite (config FauxAPI mockée), dans `tests/unit/test_dhcp_kea.py` :
     - table d'options lue depuis le pillar `pfsense:dhcp_kea:options` (`config.get` mocké) ;
     - conversion d'une option `format: hex`, d'une option avec `always-send` ;
     - refus en cas de failover, d'option absente de la table ou d'un JSON Kea divergent ;
     - pare-feu sans DHCP : aucun changement ;
     - idempotence (rerun = `{}`) ;
     - cas `numberoptions.item` réduit à un dict.
  2. Créer en lab un scénario ISC avec les options 43 et 132 sur deux interfaces. Capturer les offres DHCP, migrer avec `pfsense_dhcp_kea.migrated`, puis recapturer et comparer (V8).
  3. Vérifier que `services_dhcpd_configure` relance bien Kea, et non ISC, après la bascule.
  4. Ajouter un retour arrière : un state `pfsense_dhcp_kea.reverted` qui restaure les `numberoptions` à partir de l'`option-data`. Il ne sera ajouté que si le test lab montre qu'un retour manuel est risqué.
- Critère de fin : tests unitaires et scénarios lab verts, captures DHCP archivées dans `docs/rd/preuves/`.
- Commits :
  - `test(dhcp_kea): unit tests for ISC to Kea option conversion`
  - `test(lab): Kea migration scenario with DHCP captures`
  - `fix(dhcp_kea): …` (si le lab révèle des écarts)

### Lot 2 — Client pfrest et abstraction de backend (≈ 7 j/h)

**T2.1 `_utils/pfrest.py`, transport**
- Actions :
  - Classe `PfrestClient` avec `get`, `post`, `patch`, `delete` et `apply(domain)`, typée et sans dépendance nouvelle (`requests`, déjà utilisé).
  - Base URL : `https://127.0.0.1:<port>/api/v2/`. Le port vient de `system/webgui/port` et vaut 443 par défaut.
  - Le paramètre `verify` est configurable.
- Commit : `feat(pfrest): minimal REST client`

**T2.2 Erreurs**
- Actions :
  - Parser l'enveloppe `{code, status, response_id, message, data}`.
  - Lever une exception unique `PfrestError(code, response_id, message)`.
  - Ne jamais inclure le corps de la requête dans le message (risque de fuite de secret).
- Commit : `feat(pfrest): error envelope handling`

**T2.3 Credentials**
- Actions :
  - Lire `/usr/local/etc/salt-pfsense/api.key` : mode 600, root, une seule ligne.
  - Le chemin se surcharge par `__opts__`.
  - Ne rien logger.
- Commit : `feat(pfrest): read API key from local file`

**T2.4 Résolution d'identité (V1)**
- Actions :
  - `find_one(endpoint, parent_id=None, **key)` : filtres serveur `champ__exact`. Erreur si 0 ou plus d'un résultat (ou `None` si `allow_missing`).
  - `write_checked(method, endpoint, id, payload, key)` : relit l'objet après écriture et vérifie que la clé métier correspond toujours.
- Commit : `feat(pfrest): natural key resolution and checked writes`

**T2.5 Verrou et conflits (V2)**
- Actions :
  - Context manager `config_lock()` avec `fcntl.flock` sur `/var/run/salt-pfsense.lock`.
  - Relever la dernière révision de `config_history` à l'entrée, puis la comparer avant chaque écriture.
  - Si un tiers a écrit, lever `PfrestConflict`.
- Commit : `feat(pfrest): run lock and config revision conflict detection`

**T2.6 Dry-run et apply**
- Actions :
  - Si `__opts__['test']` est vrai, `dry_run=true` sur chaque écriture.
  - `apply(domain)` appelle `POST /<domain>/apply` avec `async=false`, puis relit l'état.
  - Le catalogue des domaines (firewall, interface, routing, dhcp, wireguard, dns_resolver) est défini une fois dans `_utils/pfrest.py`.
- Commit : `feat(pfrest): dry-run and apply helpers`

**T2.7 Sélecteur de backend**
- Actions :
  - `get_backend(module) -> Literal['fauxapi', 'pfrest']` dans `_utils/pfsense.py` : lit le pillar, puis la surcharge par module.
  - Défaut : `fauxapi`.
- Commit : `feat(utils): per-module API backend selector`

**T2.8 Lecture brute de config**
- Actions : `pfsense_config` et les modules en lecture pure (gateway, openvpn) lisent `/cf/conf/config.xml` localement (parse XML), sans aucune API.
- Commit : `feat(config): read config.xml locally`

**T2.9 Tests unitaires du client**
- Actions : couvrir toutes les branches à partir des fixtures du lot 1.
- Commit : `test(pfrest): client unit tests`

### Lot 3 — Cycle de vie du paquet pfrest (≈ 5 j/h)

**T3.1 Grain de version et carte de compatibilité**
- Actions :
  - Ajouter au grain `_grains/pfsense.py` les grains `pfsense_base` (version brute de `/etc/version`) et `pfrest_version` (lue avec `pkg info` ; vide si absent).
  - Fichier `pfrest/map.yaml` : version pfSense → version pfrest épinglée → URL de l'asset.
- Commits :
  - `feat(grains): expose raw pfSense version and pfrest version`
  - `feat(pfrest): version compatibility map`

**T3.2 Module et state `pfsense_restapi`**
- Actions :
  - `installed(version)` : `pkg-static add` de l'URL figée `releases/download/vX.Y.Z/pfSense-<base>-pkg-RESTAPI.pkg`, avec `-C /dev/null` sur Plus.
  - Idempotence basée sur le grain `pfrest_version`.
- Commit : `feat(restapi): install pinned pfrest package`

**T3.3 Bootstrap utilisateur et clé (V7)**
- Actions : helper `helpers/restapi_bootstrap.php`, qui :
  1. crée ou met à jour le groupe `salt-api`, avec ses privilèges `api-v2-*` tirés de `pfrest/privileges.yaml`, généré à partir de la matrice T0.4 ;
  2. crée ou met à jour l'utilisateur `salt-api`, avec un mot de passe aléatoire jamais stocké, puis appelle `local_user_set`/`local_group_set` ;
  3. écrit dans `installedpackages/package/<idx restapi>/conf/keys/key` l'entrée `{username, hash_algo: sha256, length_bytes: 32, descr, hash}` ;
  4. appelle `write_config()`.

  La clé en clair est générée par Salt, stockée dans le pillar chiffré, déposée dans le fichier credentials T2.3 et hachée localement. Le script reçoit seulement le hash, sur stdin et jamais en argument.
- Livrable : premier appel `GET /api/v2/system/version` réussi avec `X-API-Key`.
- Commits :
  - `feat(restapi): bootstrap dedicated API user and key hash`
  - `feat(restapi): least-privilege map`

**T3.4 Réglages déclaratifs**
- Actions : `PATCH /api/v2/system/restapi/settings` avec :
  - `enabled` ;
  - `auth_methods: [KeyAuth]` ;
  - `allowed_interfaces` = localhost ;
  - `read_only: false` ;
  - `keep_backup: true` ;
  - `login_protection` ;
  - `expose_sensitive_fields: false` ;
  - `ha_sync: false`. HA sync exige `page-all` depuis la v2.9 : on synchronise par Salt sur chaque nœud.

  Ajouter une access list `127.0.0.1/32` → `salt-api`.
- Commit : `feat(restapi): declarative package settings`

**T3.5 Après un upgrade pfSense**
- Actions :
  - Le state `pfsense_restapi.installed` est le premier état du highstate pfSense : il réinstalle le paquet s'il est absent.
  - La réinstallation restaure la clé via `backup.json`.
  - Si `backup.json` est absent, on relance le bootstrap T3.3.
- Commit : `feat(restapi): self-heal after pfSense upgrade`

**T3.6 Mise à jour pilotée de pfrest**
- Actions :
  - Monter de version uniquement en changeant `map.yaml`, après passage de la suite lab sur la nouvelle version.
  - Lancer `pfsense-restapi update` en `revert <tag>`, jamais `latest`.
- Commit : `docs(restapi): upgrade procedure`

**T3.7 Tests**
- Actions : bootstrap sur un snapshot `clean`, idempotence (2e run = 0 changement), vérification qu'aucun secret n'apparaît dans la sortie `salt-call -l debug`.
- Commit : `test(lab): restapi lifecycle scenarios`

### Lot 4 — Migration des modules couverts nativement (≈ 24 j/h)

**Procédure appliquée à chaque module** (1 PR par ligne du tableau) :
1. Ajouter la branche `pfrest` dans chaque fonction publique, derrière `get_backend()`. Le code FauxAPI reste intact.
2. Résoudre l'identité par la clé métier (T2.4), puis écrire avec `apply=false`.
3. Ajouter au state la gestion `test=True` (dry-run) et un diff `{old, new}` sur le modèle de `_states/pfsense_dhcp_static_map.py`, le seul state correct aujourd'hui.
4. Ajouter, si besoin, le state `pfsense_apply.<domaine>`.
5. Faire passer les scénarios du lot 1 sur les deux backends, avec un oracle vert ou des écarts inscrits au registre.
6. Écrire la fiche de recette du module (lot 6, format T6.1).

Commits types par module :
- `feat(<module>): pfrest backend`
- `feat(<module>): real test mode via dry_run`
- `test(<module>): pfrest scenarios`
- `docs(recipes): <module>`

| # | Module(s) | Endpoint pfrest | Clé métier | Apply | Points spécifiques |
|---|---|---|---|---|---|
| 4.1 | `pfsense_alias` | `firewall/alias` | `name` (immuable) | `firewall/apply` | `address[]` remplace la chaîne séparée par des espaces. `detail[]` est complété automatiquement : on le passe explicitement pour éviter le « Entry added ». Le diff inclut désormais `descr`. |
| 4.2 | `pfsense_cron` | `services/cron/job` | `command` + planning (l'`identifier` maison n'existe plus côté pfrest) | always_apply (`configure_cron()`) | Exige le paquet `pfSense-pkg-Cron`, à installer via `system/package`. Migrer les entrées portant `identifier` : on garde le hash calculé, sans l'écrire dans la config. |
| 4.3 | `pfsense_vlan` | `interface/vlan` | `if` + `tag` | always_apply | `vlanif` en lecture seule. Changer `if` ou `tag` détruit l'interface VLAN : on interdit la modification de clé (suppression + création explicite). |
| 4.4 | `pfsense_dhcp_static_map` | `services/dhcp_server/static_mapping` | `parent_id` = interface (`lan`, `opt1`) + `mac` | `services/dhcp_server/apply` | Le pattern pending/apply actuel devient `apply=false` + state `apply`. pfrest refuse une IP déjà prise : il faut ordonner les changements (suppressions d'abord). Le même modèle sert à ISC et à Kea : tester les deux backends. |
| 4.4b | `pfsense_dhcp_kea` (PR #6 et #7) | `services/dhcp_server/backend` (`dhcpbackend`) ; JSON Kea personnalisé via `config_path` (lot 5) si l'OpenAPI ne l'expose pas ; options ISC via l'endpoint des options personnalisées DHCP (nom exact à relever sur l'OpenAPI en T0.4) | singleton (backend) ; interface (JSON et options) | `services/dhcp_server/apply` (`dhcp_apply_changes()`), qui remplace `function_call(services_dhcpd_configure)` | Garder la logique de traduction (`numberoptions_to_kea`, `migration_changes`) indépendante du transport : seuls la lecture et l'écriture changent de backend. Le pattern `__context__` pending/apply devient `apply=false` + `pfsense_apply.dhcp`. Le backend se bascule en dernier, après écriture du JSON Kea, pour ne jamais démarrer Kea sans ses options. |
| 4.5 | `pfsense_dns` | `system/dns` | singleton, liste `dnsserver[]` | always_apply | Les passerelles par serveur (`dnsNgw`) ne sont pas exposées : on passe par le helper générique (lot 5). Le `route delete` actuel est supprimé si pfSense le gère lui-même (à vérifier). |
| 4.6 | `pfsense_syslog_configuration` | `status/logs/settings` | singleton | always_apply (`system_syslogd_start`, reload firewall si besoin) | Correspondance des noms : `enable` devient `enableremotelogging`, les autres noms sont identiques. Supprime le hack `atexit`/`HAS_CHANGES`. |
| 4.7 | `pfsense_webgui_settings` | `system/webgui/settings` | singleton | always_apply, **redémarre le WebGUI** donc coupe l'API | Seuls `protocol`, `port` et `sslcertref` sont exposés ; le reste (`nodnsrebindcheck`, `nohttpreferercheck`, `althostnames`) passe par le helper générique. Il faut attendre le retour de l'API (retry borné) avant les states suivants. |
| 4.8 | `pfsense_interface`, `pfsense_gateway` | `interface`, `routing/gateway`, `status/gateways` | id texte (`wan`, `lan`, `optN`) ; gateway par `name` | `interface/apply`, `routing/apply` | `typev4` (static/dhcp/none) remplace `ipaddr=dhcp`. `subnet` devient un entier. La suppression remplace `interface_bring_down`. `pfsense_gateway` continue de lire `/tmp/<if>_router` ou utilise `status/gateways`. |
| 4.9 | `pfsense_nat_rule` | `firewall/nat/port_forward` | aujourd'hui tuple (protocol, target, interface, local_port, disabled, source, destination), sans `descr` ; **proposé** : `descr` unique par interface | `firewall/apply` | `interface` est une chaîne et non une liste. `associated_rule_id: new` crée et maintient la règle de filtrage liée (gain fonctionnel). Le changement de clé est un changement de contrat : on garde le tuple en compatibilité et on ajoute un paramètre `match_on='descr'` opt-in. |
| 4.10 | `pfsense_filter_rule` | `firewall/rule` + `placement` | `descr` + `interface` (+ `floating`) ; `tracker` en secours | `firewall/apply` (obligatoire : pas de subsystem) | `interface` est une liste ; `source`/`destination` passent du dict à la chaîne (`any`, alias, CIDR, `lan`, `lan:ip`, `!`) ; ports dans `source_port`/`destination_port`. `tracker` est en lecture seule : on le relit après POST. `placement` est l'index global, à calculer depuis la position souhaitée dans l'interface. Ajoute la mise à jour des règles existantes (PATCH), qui n'existe pas aujourd'hui. Mesurer les reloads pf (V3). |
| 4.11 | `pfsense_user`, `pfsense_ssh` | `user`, `user/group` | `name` | always_apply (`local_user_set`/`local_group_set`) | pfrest crée le compte FreeBSD : on supprime les appels `user.add`/`shadow.set_password`/`user.chshell`. `password` est envoyé en clair et haché côté serveur, donc l'idempotence n'est plus comparable : on ne l'envoie qu'à la création ou si `password_changed=True`. `authorizedkeys` est en clair (pfrest encode en base64). `pfsense_ssh` lit et écrit via `user.authorizedkeys` avec `append`/`remove`. |
| 4.12 | `pfsense_certificate`, state `pfsense_user_cert` | `system/certificate/generate`, `system/certificate`, `system/certificate_authority`, `system/crl/revoked_certificate` (`parent_id` = CRL) | cert : `refid` ; cert utilisateur : `descr` = nom | generate et CRL en always_apply ; import sans apply | Remplace `cert_create.php` : `keytype=RSA`, `keylen=2048`, `digest_alg=sha256`, `lifetime=3650`, `type=user`, et DN en pillar (`pfsense:pki:dn`) au lieu du DN codé en dur. Remplace `crl_revoke.php` (POST `revoked_certificate`). Le dé-révocation devient DELETE, ce qui rend possible le state `revoked` aujourd'hui inopérant. Le serial de la CA est géré par pfSense : on supprime `_increase_ca_serial`. |
| 4.13 | `pfsense_wireguard` | `vpn/wireguard/peer` (+ `allowed_ip`), `vpn/wireguard/tunnel` | peer : `publickey` (unique) ; tunnel : `name` | `vpn/wireguard/apply` | Le peer est **désactivé par défaut** côté pfrest : il faut passer `enabled` explicitement. `allowedips[]` = `{address, mask, descr}`. Remplace `regenerate_wireguard.php`. Ajoute update et remove, absents aujourd'hui, et un state `pfsense_wireguard_peer`. |
| 4.14 | `pfsense_openvpn` (lecture), `pfsense_user.export_openvpn_config` | `vpn/openvpn/server`, `vpn/openvpn/client_export` | serveur : `vpnid` ; export : `server` + `username` + `certref` | — | Exige `pfSense-pkg-openvpn-client-export`. `type` reprend les valeurs actuelles (`confzip`, `confinline`, `visc`, `inst-*`). Paramètres `bindmode=nobind` et `p12encryption=high` comme dans `helpers-23XXRELEASE`. Le binaire est reçu via `Accept: application/octet-stream` et écrit sur le minion. Supprime les 4 variantes `helpers-*RELEASE/export_openvpn_config.php`. |

Ordre de passage : du plus simple au plus critique (4.1 → 4.14). Chaque module bascule en prod pilote (lot 7) dès qu'il est vert, sans attendre la fin du lot.

### Lot 5 — Comblement des manques fonctionnels (≈ 9 j/h)

**T5.1 Helper générique `helpers/config_path.php`**
- Actions :
  - Interface : `get <path>`, `set <path>` (JSON sur stdin) et `delete <path>`, via `config_get_path`/`config_set_path`, puis `write_config("salt-pfsense: <desc>")`.
  - Le chemin est validé contre une allowlist (`helpers/config_path.allow`).
  - Le script prend le même verrou que T2.5.
- Commit : `feat(helpers): generic allowlisted config path helper`

**T5.2 Prototype d'un endpoint custom pfrest (V4)**
- Actions :
  - Créer `SystemWebGUIAltHostnames` dans `/usr/local/pkg/RESTAPI/{Models,Endpoints}/`, puis lancer `pfsense-restapi buildendpoints`.
  - Mesurer sa survie à `pfsense-restapi update` (attendu : effacé) et le coût de son redéploiement par Salt.
- Livrable : note de décision dans `docs/rd/journal.md`.
- Commit : `test(rd): custom pfrest endpoint prototype`

**T5.3 Migration des manques**

| Besoin | Mécanisme retenu par défaut (révisable après T5.2) | Application |
|---|---|---|
| `pfsense_althostname` | `config_path` sur `system/webgui/althostnames` | aucune (lue par nginx au prochain restart WebGUI) |
| `pfsense_sshguard_whitelist` | `config_path` sur `system/sshguard_whitelist` | `filter_configure()` + `system_syslogd_start()` (fusion dans un helper `apply_sshguard.php`) |
| `pfsense_if_pppoe` | `config_path` sur `system/use_if_pppoe` | reboot planifié (inchangé) |
| `pfsense_be` | `manage_bootenv.php` inchangé ; chemin unifié `/opt/helpers` (fin de `/scripts`) | — |
| `pfsense_sudo_configuration` | `config_path` sur `installedpackages/sudo/config/0` | `sudo_write_config()` (resync du paquet, ajouté) |
| `pfsense_zabbix_configuration` | `config_path` sur `installedpackages/zabbixagentlts/config/0` | resync du paquet zabbix (ajouté) |
| `pfsense_dns` (gateways) | `config_path` sur `system/dnsNgw` | `system_resolvconf_generate()` |
| WebGUI (clés non exposées) | `config_path` sur `system/webgui/<clé>` | `restart_webgui` |

Commits : un `feat(<module>): …` par ligne.

**T5.4 Politique `command_prompt`**
- Actions : documenter l'interdiction de `command_prompt`. Le privilège n'est jamais accordé, et un test vérifie qu'il est absent de `privileges.yaml`.
- Commit : `test(restapi): command prompt privilege never granted`

### Lot 6 — Recettes de déploiement Salt (documentation testée) (≈ 6 j/h)

Objectif : qu'un administrateur Salt sans connaissance du code puisse déployer, exploiter et faire évoluer la solution sur un pare-feu, uniquement à partir des recettes. Chaque recette est **exécutée en lab par la CI** : la documentation ne peut pas dériver du code.

**T6.1 Format d'une recette**

Fichier `docs/recipes/NN-<sujet>.md`. Sections fixes :
1. Objectif ;
2. Prérequis ;
3. Pillar d'exemple ;
4. SLS d'exemple ;
5. Commande ;
6. Sortie attendue en `test=True` ;
7. Vérification ;
8. Retour arrière ;
9. Pièges connus.

Les pillars et sls cités vivent en vrais fichiers dans `examples/pillar/` et `examples/salt/`. Le markdown les inclut par chemin, sans copie.

Commit : `docs(recipes): recipe template and index`

**T6.2 Recettes « socle »**

| # | Recette | Contenu |
|---|---|---|
| 00 | Architecture et prérequis | schéma master/minion local, flux `127.0.0.1`, versions Salt supportées (3006 LTS jusqu'en 2027-06, 3008 LTS), matrice pfSense/pfrest |
| 01 | Installer le minion Salt sur pfSense | `pkg add` d'une URL `pkg.freebsd.org` correspondant à l'ABI (sans activer le dépôt FreeBSD), `sysrc salt_minion_enable=YES`, sauvegarde de `/usr/local/etc/salt` (clés minion), test `salt-call test.ping` |
| 02 | Distribuer les extensions | `file_roots` ou `gitfs` pointant sur le dépôt, `saltutil.sync_all` (ou `sync_modules`/`sync_states`/`sync_grains`/`sync_utils`), vérification `saltutil.list_extmods` |
| 03 | Déployer les helpers PHP | `file.recurse` vers `/opt/helpers` (mode 700, root), suppression de `/scripts` |
| 04 | Gérer les secrets | pillar chiffré (renderer `gpg`, ou ext_pillar Vault, ou `sdb`), génération de la clé API, `show_changes: False`, vérification d'absence dans `salt-call -l debug` |
| 05 | Installer et amorcer pfrest | `pfsense_restapi.installed` + bootstrap + réglages (lot 3) ; choix de version via `map.yaml` |
| 06 | Basculer un pare-feu de FauxAPI vers pfrest | pillar `pfsense:api_backend`, surcharge par module, run `test=True` puis réel, contrôle d'idempotence |
| 07 | Ordonnancer les applies | pattern `onchanges` vers `pfsense_apply.firewall` / `interface` / `dhcp` / `wireguard` ; anti-pattern d'un apply par objet |

**T6.3 Recettes par domaine**

Une recette par state, chacune avec un exemple complet et réaliste :
- 10 alias ;
- 11 règles de filtrage, ordre et `placement` compris ;
- 12 NAT port forward avec règle associée ;
- 13 utilisateurs et groupes ;
- 14 clés SSH ;
- 15 PKI : création d'un certificat utilisateur, révocation, dé-révocation ;
- 16 export OpenVPN ;
- 17 peers WireGuard ;
- 18 DHCP static mappings, ISC et Kea ;
- 18b Migrer le DHCP d'ISC vers Kea : prérequis (classement T0.6), `pfsense_dhcp_kea.migrated` en `test=True` puis réel, contrôle par capture DHCP, gestion des refus (failover, option inconnue), retour arrière ;
- 19 VLAN et interfaces ;
- 20 DNS système ;
- 21 syslog distant ;
- 22 cron ;
- 23 WebGUI et althostnames ;
- 24 sshguard ;
- 25 sudo et zabbix-agent ;
- 26 PPPoE kernel ;
- 27 boot environments.

**T6.4 Recettes d'exploitation**

| # | Recette | Contenu |
|---|---|---|
| 40 | Déploiement sur le parc | `salt-run state.orchestrate` avec `batch: 1` puis `10%`, `failhard: True`, paires HA traitées nœud par nœud |
| 41 | Haute disponibilité | appliquer sur chaque nœud (pas de HA sync pfrest), ou sur le primaire puis `rc.filter_synchronize` ; arbitrage documenté |
| 42 | Après un upgrade pfSense | réinstallation automatique de pfrest, vérification de la clé, highstate |
| 43 | Monter de version pfrest | mise à jour de `map.yaml` après passage de la suite lab |
| 44 | Retour arrière | rebascule du pillar sur `fauxapi` (tant que le lot 8 n'est pas fait), restauration de config via l'historique pfSense (WebGUI) |
| 45 | Dépannage | codes `response_id` fréquents, conflit `PfrestConflict`, API coupée après restart WebGUI, privilège manquant (`403`), lecture des logs pfrest |

**T6.5 Test des recettes**
- Actions :
  - `tests/lab/test_recipes.py` applique chaque sls de `examples/salt/` sur le lab, en `test=True` puis en réel puis en idempotence.
  - Un linter vérifie que chaque recette contient les 9 sections de T6.1 et que chaque fichier inclus existe.
- Critère de fin : CI lab verte sur toutes les recettes.
- Commits :
  - `test(recipes): run example states on lab`
  - `test(recipes): lint recipe structure`

### Lot 7 — Déploiement progressif sur le parc (≈ 6 j/h)

**T7.1 Pilote**
- Actions :
  - Choisir un pare-feu non critique dans la colonne v2.10.x.
  - Lui appliquer, dans l'ordre :
    1. recettes 01 à 05 ;
    2. bascule module par module (recette 06), dans l'ordre du lot 4 ;
    3. pour chaque module : run en `test=True`, diff vide attendu, puis run réel, puis 2e run à 0 changement.
  - Observer une semaine (supervision, journaux pfrest).
- Livrable : `docs/migration/journal-deploiement.md`.

**T7.2 Vagues**
- Actions :
  - Vague 1 : 10 % du parc, versions les plus récentes.
  - Vague 2 : 50 %.
  - Vague 3 : le reste, paires HA en dernier.
  - Chaque vague passe par la recette 40 et une fenêtre d'observation de 3 jours.

**T7.3 Haute disponibilité**
- Actions :
  - Valider sur une paire de lab la stratégie de la recette 41.
  - Vérifier qu'il n'y a pas de double écriture ni de dérive entre nœuds : diff `config.xml` des deux nœuds après run, via l'oracle.

**T7.3b Migration Kea sur le parc**
- Actions :
  - Dérouler la recette 18b sur les pare-feux classés « migrable automatiquement » en T0.6, par vagues, indépendamment de la bascule pfrest.
  - Les pare-feux « manuel » (failover) suivent une procédure dédiée, documentée dans la recette.
- Critère de fin : 100 % des pare-feux migrables sur Kea, captures avant et après archivées.

**T7.4 Pare-feux hors matrice**
- Actions :
  - Les pare-feux du périmètre sur une version non couverte par v2.10.2 (CE 2.7.x, Plus 25.11) passent d'abord en CE 2.8.1/2.9.0 ou Plus 26.07, puis entrent dans une vague.
  - Les pare-feux hors périmètre (FreeBSD < 14) restent sur FauxAPI, sans évolution.

**T7.5 Indicateurs**
- Actions : relever pour chaque vague les indicateurs de la section dédiée.

Commits : uniquement de la documentation (`docs(migration): wave N report`) et les correctifs révélés par le terrain (`fix(...)` avec test).

### Lot 8 — Décommissionnement et capitalisation (≈ 4 j/h)

**T8.1 Retrait de FauxAPI**
- Préalable : 100 % du périmètre (FreeBSD ≥ 14) en pfrest depuis 30 jours.
- Actions :
  - Désinstaller FauxAPI des pare-feux du périmètre (state `absent`) et supprimer `/etc/fauxapi/credentials.ini`.
  - Supprimer `FauxapiLib` et les branches `fauxapi` des modules seulement quand aucun pare-feu hors périmètre ne reste en service (mis à jour ou remplacé). D'ici là, le backend FauxAPI est gelé : aucune évolution, corrections de sécurité uniquement.
- Commits :
  - `refactor(utils): drop fauxapi backend`
  - `feat(fauxapi): uninstall state`

**T8.2 Nettoyage**
- Actions : supprimer les helpers remplacés (`cert_create.php`, `crl_revoke.php`, `crl_unrevoke.php`, `regenerate_wireguard.php`, `resolvconf.php` ×2, `nat_rule.php`, `pkg_manager.php` si confirmé mort, `helpers-*RELEASE/`) et le code mort du lot 0.
- Commit : `chore: remove obsolete helpers and dead code`

**T8.3 Documentation finale**
- Actions : README (présentation, installation, renvoi vers les recettes), CHANGELOG, registre d'écarts final.
- Commit : `docs: README and changelog`

**T8.4 Synthèse R&D**
- Actions : écrire `docs/rd/synthese.md` : pour chaque verrou V1 à V8, l'hypothèse, les expériences menées, les résultats chiffrés, la solution retenue, les échecs et leurs enseignements.
- Commit : `docs(rd): final synthesis`

**Charge totale indicative : ≈ 80 j/h**, dont environ 4 j/h pour Kea (T0.6, T1.8, 4.4b, recette 18b, T7.3b) et environ 2 j/h de documentation R&D au fil de l'eau.

---

## Documentation R&D (`docs/rd/`), base du dossier CIR

`docs/rd/` est la partie recherche. Elle est structurée dès le lot 0 pour qu'on puisse en extraire directement le dossier justificatif CIR, sans le réécrire après coup. Elle ne contient aucun nom de client, d'équipement nominatif ou d'entreprise : les pare-feux y sont désignés par un identifiant anonyme (`FW-01`, `FW-02`…), avec la correspondance tenue hors dépôt.

```
docs/rd/
├── README.md               index, conventions d'anonymisation, comment générer le dossier
├── 01-contexte.md          problème, enjeux, périmètre, objectifs mesurables
├── 02-etat-de-l-art.md     solutions existantes et pourquoi elles ne suffisent pas, références datées et liens
├── 03-verrous.md           V1 à V8 : description, hypothèse, protocole, critère de levée, statut
├── 04-demarche.md          méthode expérimentale (lab, oracle, captures, mesures), outils, reproductibilité
├── 05-experiences/         une fiche par expérience : EXP-NN-<verrou>-<sujet>.md
│                           (date, hypothèse testée, protocole, résultats bruts, analyse, conclusion, commits/PR liés)
├── 06-resultats.md         résultats par verrou, indicateurs avant/après, échecs et leurs enseignements
├── 07-contribution.md      ce qui est nouveau par rapport à l'état de l'art (bootstrap sans secret, résolution
│                           d'identité, oracle config.xml, traduction ISC→Kea…)
├── journal.md              journal de bord hebdomadaire : date, tâche, verrou, résultat, temps passé, lien PR
├── temps.csv               date, personne (initiales), tâche, verrou, heures ; sert au calcul des dépenses de personnel
├── preuves/                captures DHCP, sorties de mesures, extraits d'oracle (anonymisés)
└── synthese.md             (lot 8) document final reprenant 01→07 sous la forme du dossier justificatif
```

**Règles de tenue :**
- **Chaque PR** cite le ou les verrous concernés (`Refs: V1, V5`) et, si elle porte une expérience, la fiche `EXP-NN`.
- **Chaque expérience**, réussie ou non, a sa fiche : les échecs documentés démontrent l'incertitude, ce qui est attendu par le CIR.
- **Le journal et `temps.csv`** sont mis à jour dans chaque PR de lot (`docs(rd): lot N log`).
- **Séparation de l'opérationnel.** La part R&D (verrous, expérimentations, prototypes) est distinguée de la part de développement courant (migration mécanique de modules, recettes, déploiement) : chaque ligne de `temps.csv` porte une catégorie `rd` ou `dev`, pour ne déclarer que l'éligible.
- **Données sensibles.** Aucun secret ni aucune donnée client dans `preuves/`. Le linter du lot 6 vérifie aussi `docs/rd/` : il refuse noms de domaine internes, IP publiques et noms d'hôtes non anonymisés (motifs en pillar ou en fichier ignoré par Git).

Expériences prévues (fiches `05-experiences/`) :

| Fiche | Verrou | Lot |
|---|---|---|
| EXP-01 Stabilité des identifiants sous suppressions/insertions | V1 | 2 |
| EXP-02 Écritures concurrentes WebGUI / Salt / HA | V2 | 2 |
| EXP-03 Nombre de reloads pf et durée de run, avant/après | V3 | 4 |
| EXP-04 Endpoint custom vs helper générique face aux mises à jour | V4 | 5 |
| EXP-05 Oracle `config.xml` : écarts FauxAPI / pfrest par module | V5 | 4 |
| EXP-06 Suite de contrat sur chaque version pfrest épinglée | V6 | 3 |
| EXP-07 Bootstrap de clé sans compte admin | V7 | 3 |
| EXP-08 Équivalence des offres DHCP ISC / Kea | V8 | 1 |

---

## Enchaînement des lots

**Règle.** Un lot = une branche + une PR. Le lot suivant ne démarre qu'une fois la PR du lot précédent mergée. Chaque branche part de `origin/master` à jour (`git fetch origin && git rebase origin/master` avant push).

**Avant le lot 0 :** une PR `docs/migration-plan` versionne ce plan dans `docs/migration/plan.md`.

| Ordre | Lot | Branche | Titre de PR |
|---|---|---|---|
| 0 | Plan | `docs/migration-plan` | `docs(migration): pfrest migration plan` |
| 1 | Lot 0 | `docs/lot-0-inventory` | `docs(migration): lot 0 - inventory and scoping` |
| 2 | Lot 1 | `chore/lot-1-quality-lab` | `chore: lot 1 - tooling, lab, oracle and Kea` |
| 3 | Lot 2 | `feat/lot-2-pfrest-client` | `feat(pfrest): lot 2 - client and backend selector` |
| 4 | Lot 3 | `feat/lot-3-restapi-lifecycle` | `feat(restapi): lot 3 - package lifecycle and bootstrap` |
| 5 | Lot 4 | `feat/lot-4-modules` | `feat: lot 4 - modules on pfrest` |
| 6 | Lot 5 | `feat/lot-5-gaps` | `feat: lot 5 - functional gaps` |
| 7 | Lot 6 | `docs/lot-6-recipes` | `docs(recipes): lot 6 - Salt deployment recipes` |
| 8 | Lot 7 | `docs/lot-7-rollout` | `docs(migration): lot 7 - progressive rollout` |
| 9 | Lot 8 | `chore/lot-8-decommission` | `chore: lot 8 - decommission fauxapi` |

**Contenu de chaque PR :**
- au moins un commit par tâche du lot, au format `type(scope): message` ;
- `pre-commit run --all-files` et `pytest` verts dès qu'ils existent (lot 1) ;
- description : tâches couvertes, verrous concernés (`Refs: Vn`), expériences (`EXP-NN`), ce qui reste à exécuter en lab ;
- mise à jour de `docs/rd/journal.md` et `docs/rd/temps.csv`.

Les commits sont datés du jour où le travail est fait : aucune réécriture de date. L'historique Git, les PR et le journal de bord forment ainsi une trace chronologique fidèle des travaux.

Les tâches qui demandent le lab ou l'accès au parc sont préparées dans la PR (code, tests, checklist) ; la PR indique ce qui reste à exécuter en lab avant merge.

---

## Indicateurs de résultat

- **Couverture :** % de fonctions publiques servies par un endpoint natif, par `config_path` ou par un helper dédié.
- **Idempotence :** 2e highstate à 0 changement sur 100 % des scénarios et des recettes.
- **Test mode :** 100 % des states renvoient `result=None` et un diff réel en `test=True` (contre 4 states cassés aujourd'hui).
- **Équivalence :** 0 écart `config.xml` hors registre.
- **Performance :** durée d'un highstate, nombre de lectures complètes de config, nombre de reloads pf, avant et après.
- **Sûreté :** 0 écriture sur un mauvais objet (V1) ; 100 % des conflits détectés (V2).
- **Robustesse :** cycle upgrade pfSense → réinstallation pfrest → highstate, sans intervention, sur chaque version de la matrice.
- **Sécurité :** 0 secret dans les logs et les sorties Salt (test automatisé) ; utilisateur API sans `page-all` ni `command_prompt`.

## Fichiers critiques

- `_utils/pfsense.py` : `FauxapiLib`, conservé jusqu'au lot 8, plus `get_backend()`.
- `_utils/pfrest.py` (nouveau) : client, erreurs, identité, verrou, dry-run, apply.
- `_modules/pfsense_*.py` : branche `pfrest` derrière le sélecteur ; signatures inchangées.
- `_states/pfsense_*.py` : test mode réel, diff `{old, new}` ; nouveaux `pfsense_apply`, `pfsense_restapi`, `pfsense_wireguard_peer`.
- `_grains/pfsense.py` : `pfsense_base`, `pfrest_version`.
- `helpers/config_path.php`, `helpers/restapi_bootstrap.php` (nouveaux) ; anciens helpers supprimés au lot 8.
- `pfrest/map.yaml`, `pfrest/privileges.yaml` (nouveaux).
- `tests/` (nouveau) : unitaires, fixtures, oracle, scénarios lab, test des recettes.
- `docs/recipes/`, `examples/salt/`, `examples/pillar/`, `docs/migration/`, `docs/rd/` (nouveaux).

Code existant à réutiliser :
- motifs de masquage `SENSITIVE_KEYS`/`SENSITIVE_PATTERNS` : `_modules/pfsense_config.py` ;
- pattern pending/apply et diff `{old, new}` : `_modules/pfsense_dhcp_static_map.py` et `_states/pfsense_dhcp_static_map.py` ;
- lecture du fichier de credentials : `_utils/pfsense.py:_get_apikey` ;
- `_check_ip` : `_modules/pfsense_sshguard_whitelist.py`.

## Vérification

- À chaque PR : `pre-commit run --all-files` et `pytest`, unitaires en CI.
- Par module migré : `pytest -m lab --backend=fauxapi` puis `--backend=pfrest` sur le lab, oracle `config.xml` vert.
- Par recette : `pytest tests/lab/test_recipes.py -k <recette>`, avec `test=True`, réel et idempotence.
- Sur le pilote :
  - `salt <minion> state.apply test=True` affiche un diff vide après bascule ;
  - le run réel suivi d'un 2e run donne 0 changement ;
  - `salt-call -l debug` ne fait apparaître aucune clé API.

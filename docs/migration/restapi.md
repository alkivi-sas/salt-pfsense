# Cycle de vie de pfSense-pkg-RESTAPI (lot 3)

Ce document décrit comment le paquet pfrest est installé, amorcé, configuré et maintenu sur chaque pare-feu du périmètre ([`versions.md`](versions.md)), sans aucun mot de passe administrateur.

## Composants

| Élément | Rôle |
|---|---|
| `_utils/pfrest_lifecycle.py` | version épinglée (`v2.10.2`), bases supportées, URL de l'asset, commande d'installation, liste des privilèges, hash de clé, réglages par défaut |
| `_modules/pfsense_restapi.py` | `install`, `bootstrap`, `configure`, `status`, `installed_version` |
| `_states/pfsense_restapi.py` | `installed`, `bootstrapped`, `configured` |
| `helpers/restapi_bootstrap.php` | création ou mise à jour du groupe et de l'utilisateur `salt-api`, de l'entrée de clé (hash seul), activation de `KeyAuth` |
| `_grains/pfsense.py` | `pfsense_base`, `pfsense_edition`, `pfrest_version` |

## Pillar

```yaml
pfsense:
  restapi:
    api_key: <64 caractères hexadécimaux, depuis le pillar chiffré>
    settings: {}        # surcharge éventuelle de DEFAULT_SETTINGS
    access_list:        # par défaut : une seule entrée, la boucle locale
      - network: 127.0.0.1/32
```

La clé est générée hors du pare-feu : `openssl rand -hex 32`. Le pare-feu n'en stocke que le hash (`sha256(clé)`), dans `installedpackages/package/<RESTAPI>/conf/keys/key`. Le minion garde la clé en clair dans `/usr/local/etc/salt-pfsense/api.key`, en mode 0600, et l'utilise pour l'en-tête `X-API-Key`.

## Ordre dans le highstate

1. `pfsense_restapi.installed` : installe `v2.10.2` si le paquet est absent. Sur Plus, `pkg-static -C /dev/null add <asset>` ; sur CE, sans `-C`. Si une autre version est installée, il passe à la version épinglée avec `pfsense-restapi revert v2.10.2`.
2. `pfsense_restapi.bootstrapped` : écrit le fichier de clé, puis lance le helper avec la requête sur l'entrée standard, sortie masquée. Il est idempotent.
3. `pfsense_restapi.configured` : `PATCH system/restapi/settings`, puis l'access list.
   - Réglages appliqués : `enabled`, `auth_methods: [KeyAuth]`, `keep_backup`, `login_protection`, `expose_sensitive_fields: false`, `ha_sync: false`, `hateoas: false`, `represent_interfaces_as: id`.
   - `represent_interfaces_as: id` est indispensable : les modules utilisent les identifiants `wan`, `lan`, `optN`. Avec la valeur par défaut, `descr`, l'API exposerait les noms affichés.

## Privilèges

L'utilisateur `salt-api` est membre du groupe `salt-api`. Ce groupe ne reçoit que les privilèges `api-v2-<endpoint>-<méthode>` des endpoints listés dans `pfrest_lifecycle.ENDPOINTS`.
- **Jamais** `page-all`.
- **Jamais** `api-v2-diagnostics-command-prompt-post` : exécution shell non échappée.

Un test vérifie que chaque endpoint et chaque méthode existent dans le contrat de la version épinglée (`pfrest/contract/v2.10.2.json`).

## Après une mise à jour de pfSense

pfSense supprime les paquets non officiels lors d'une mise à jour. Au highstate suivant :
1. `installed` réinstalle le paquet ;
2. le paquet restaure sa configuration (clés, réglages) depuis `backup.json` (`keep_backup`) ;
3. `bootstrapped` réécrit l'entrée de clé si elle manque.

Seule condition : la nouvelle base pfSense doit avoir un asset pour la version épinglée. Sinon, `installed` échoue explicitement.

## Monter la version épinglée

1. Télécharger l'`openapi.json` de la nouvelle release et régénérer le contrat : `pipenv run python pfrest/extract_contract.py openapi.json vX.Y.Z pfrest/contract/vX.Y.Z.json`.
2. Lancer les tests unitaires sur le nouveau contrat (`tests/fake_pfrest.py` le charge) et corriger les écarts : champs renommés, nouvelles contraintes.
3. Mettre à jour `PFREST_VERSION` et `SUPPORTED_BASES` à partir des assets de la release.
4. Déployer par vagues (lot 7) : `installed` exécute alors `pfsense-restapi revert vX.Y.Z`.

Ne jamais utiliser `latest` : les versions mineures de pfrest contiennent des changements cassants (voir [`coverage.md`](coverage.md)).

## Non vérifié sans lab

- Effet de l'access list : savoir si une seule entrée `allow` sur 127.0.0.1/32 refuse les autres sources.
- Restauration effective de `backup.json` après une mise à jour de pfSense.
- Comportement de `local_user_set_password` et de `local_group_set` appelés depuis le helper en CLI.

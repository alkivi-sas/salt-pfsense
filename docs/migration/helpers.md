# Déploiement des helpers et de FauxAPI (T0.3)

Relevé du 2026-10-19 dans le dépôt de states SaltStack.

## Helpers PHP

Le SLS `pfsense/api/helpers.sls` est inclus par `pfsense/api/init.sls` :
1. `file.recurse` de `helpers/` vers `/opt/helpers`, avec `include_pat: "*.php"` ;
2. `file.recurse` du dossier propre à la version, choisi par `pfsense['helpers']`, toujours vers `/opt/helpers` : il écrase les fichiers communs de même nom ;
3. dépôt de `ipsec_test.sh` en mode 750.

Les deux `file.recurse` n'ont ni `file_mode` ni `dir_mode`. La seule cible est `/opt/helpers` : rien n'est déployé dans `/scripts`.

### Choix du dossier selon la version

`pfsense/map.jinja` fusionne trois sources : `defaults.yaml`, puis `versionmap.yaml` filtré par le grain `version`, puis le pillar `pfsense`.

| Grain `version` | Dossier déclaré | Dossier réel dans ce dépôt |
|---|---|---|
| `244RELEASE` | `helpers-244RELEASE` | `helpers-244RELEASE` |
| `245RELEASE` | `helpers-245RELEASE` | `helpers-245RELEASE` |
| `250`, `251`, `252`, `260`, `21052`, `2201`, `2205`, `2301`, `2305` RELEASE | `helpers-25xRELEASE` (lien) | `helpers-250RELEASE` |
| `2309RELEASE` | `helpers-23XXRELEASE` | `helpers-23XXRELEASE` |
| toute autre version (défaut) | `helpers-24XXRELEASE` (lien) | `helpers-23XXRELEASE` |

Seuls deux fichiers diffèrent d'une version à l'autre : `export_openvpn_config.php` (signature du paquet d'export OpenVPN) et `resolvconf.php` (244 uniquement).

Le cas par défaut couvre toutes les versions récentes du parc : 2.7.x, 2.8.x, 2.9.x et Plus 24.x à 26.x (voir [`versions.md`](versions.md)). Ces versions utilisent donc `helpers-23XXRELEASE`.

### Écarts

- **Chemin de `manage_bootenv.php`.** `_modules/pfsense_be.py` appelle `/scripts/manage_bootenv.php`, mais le helper est déployé dans `/opt/helpers` (voir [`usage.md`](usage.md)).
- **Nommage trompeur.** Deux noms de dossier (`helpers-24XXRELEASE`, `helpers-25xRELEASE`) ne sont que des liens vers d'autres dossiers.

## FauxAPI

Le SLS `pfsense/api/init.sls` fait les opérations suivantes.

1. **Installation.** Il dépose deux scripts dans `/tmp`, en mode 755 :
   - `install_fauxapi.sh` télécharge le paquet `pfSense-pkg-FauxAPI-1.4_1.txz` depuis le dépôt de paquets de FauxAPI, puis l'installe avec `pkg-static install -U` ;
   - `test_fauxapi.sh` contrôle la version via `pkg info`.

   Le state `cmd.run` exécute l'installation, sous condition `unless` sur le script de test.
2. **Fichier de credentials.** `/etc/fauxapi/credentials.ini` est produit à partir d'un template, en root:wheel 0600, après l'installation.
   - La clé et le secret sont dérivés par un module Salt maison de génération de mots de passe ; ils ne viennent pas du pillar.
   - Le template contient aussi deux clés statiques, `owner` et `permit`.
   - Il ajoute `host` si le pillar `fauxapi:host` est défini.
3. **Fonctions autorisées.** `/etc/fauxapi/pfsense_function_calls.txt` (root:wheel 0600) liste les fonctions PHP que `function_call` peut exécuter, soit 1 092 lignes.
4. **Correctif local.** Si le grain `version` vaut `2403RELEASE` ou `2411RELEASE`, `/etc/inc/fauxapi/fauxapi_pfsense_interface.inc` est remplacé par une version corrigée (0644). FauxAPI ne fonctionne donc plus sans correctif sur les versions récentes.

## Conséquences pour le plan

- **Lot 3.** Le cycle de vie de pfrest reprend le schéma existant : script d'installation figé, test d'idempotence, fichier de credentials en 0600.
  - Le grain doit distinguer CE et Plus : `-C /dev/null` sur Plus.
  - Le grain doit aussi repérer les architectures non supportées.
  - La clé pfrest peut être dérivée par le même module maison que FauxAPI, ce qui évite un nouveau secret à stocker. À valider au lot 3 (V7).
- **Lot 8.** Supprimer `pfsense/api/` côté FauxAPI : scripts, credentials, liste de fonctions et correctif. Simplifier `versionmap.yaml`, qui ne servira plus qu'à `zabbix_pkg`, `zabbix_pkg_absent` et `default_packages`.
- **Lot 1 (T1.7).** Corriger le chemin de `pfsense_be` vers `/opt/helpers`.

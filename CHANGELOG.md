# Changelog

## Non publié

### Ajouts

- **Backend pfSense REST API v2 (pfrest)**, choisi par pillar et par module. Il couvre alias, règles de filtrage, NAT, utilisateurs et groupes, clés SSH, cron, VLAN, static maps DHCP, serveurs DNS, interfaces et passerelles, certificats et CRL, export OpenVPN et pairs WireGuard.
- **Helper générique `config_path.php`** sur liste blanche, pour ce que pfrest ne modélise pas : althostnames, sshguard, PPPoE noyau, sudo, agent zabbix, clés WebGUI, passerelles DNS, syslog `numberofitems`, JSON Kea.
- **Cycle de vie de pfrest :**
  - state `pfsense_restapi` (installation épinglée, amorçage sans mot de passe administrateur, réglages) ;
  - privilèges minimaux dérivés des endpoints utilisés.
- **State `pfsense_apply`** pour l'application différée par domaine.
- **Grains** `pfsense_base`, `pfsense_edition` et `pfrest_version`.
- **Migration DHCP ISC → Kea** (`pfsense_dhcp_kea`), sur les deux backends.
- **Outillage :**
  - environnement pipenv, pre-commit (black, flake8, mypy) et CI ;
  - tests unitaires, faux serveur pfrest validé par le contrat, tests des helpers PHP ;
  - oracle `config.xml` et scénarios de lab.
- **Documentation :** recettes de déploiement (`docs/recipes/`), plan et inventaires de migration (`docs/migration/`), documentation R&D (`docs/rd/`).

### Corrections

- `pfsense_be` : chemin du helper (`/opt/helpers`).
- `pfsense_ssh` : journalisation sur les fichiers de clés invalides.
- `pfsense_wireguard` : message de clé publique en double.
- `pfsense_vlan` : création du premier VLAN, mode test, `present` idempotent.
- `pfsense_cron` : mode test et idempotence avec un planning entier.
- `pfsense_interface` : `need_changes`, mode test, `present` idempotent.
- `pfsense_filter_rule` : `absent`.
- `pfsense_user` : export OpenVPN du premier certificat, mot de passe réécrit à chaque passage.
- `pfsense_certificate` : création de certificat utilisateur sous Python 3.

### Suppressions

- Helpers jamais appelés : `crl_unrevoke.php`, `nat_rule.php`, `resolvconf.php` (deux copies).

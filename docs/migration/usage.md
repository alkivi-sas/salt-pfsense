# Usage des modules (T0.2)

Relevé du 2026-10-19 dans le dépôt de states SaltStack qui consomme ce dépôt. Les noms des fichiers propres à un client sont anonymisés.

## Intégration

Ce dépôt est un **submodule** du dépôt de states. Il y est raccordé par des liens symboliques :
- `_modules/pfsense_*.py`, `_states/pfsense_*.py` et `_utils/pfsense.py` pointent vers le submodule ;
- les dossiers `helpers*` sont exposés sous `pfsense/files/`.

Le point d'entrée est `pfsense/post_install.sls`. Il inclut `api`, `zabbix` et `rrd`, puis, hors nœud de secours (`-backup`) :

`ssh`, `guest_alias`, `admin_alias`, `althostname`, `packages`, `sshguard_whitelist`, `blacklist`, `crl_patch`, `dhcp.kea`

Il ajoute `cloud` pour les pare-feux hébergés.

D'autres consommateurs appellent les modules en exécution directe, sans SLS :
- un outil interne d'administration (VPN) : `pfsense_user.list_users`, `add_user`, `export_openvpn_config`, `pfsense_openvpn.get_server`, `pfsense_certificate.get_cert`, `add_user_certificate`, `get_crl_revoked_list` ;
- deux outils de maintenance (mises à jour, boot environments), qui lancent directement `php /opt/helpers/manage_bootenv.php` et `php /opt/helpers/pkg_manager.php` ;
- la gateway MCP en lecture : `pfsense_config.*`.

## Références par famille

| Famille | Fonctions utilisées | Références SLS | Priorité de migration |
|---|---|---|---|
| `pfsense_alias` | `present` | 25 (commun : alias d'administration, invités, liste noire, téléphonie ; plusieurs SLS client) | haute |
| `pfsense_syslog_configuration` | `present` ×18, `force_reload` ×1 | 19 | haute |
| `pfsense_filter_rule` | `absent` ×8, `present` ×6 | 14 | haute |
| `pfsense_user` | `present` | 10 (dont plusieurs SLS client) | haute |
| `pfsense_cron` | `present` ×6, `absent` ×3 | 9 | moyenne |
| `pfsense_interface` | `list_wan_interfaces` ×4, `list_lan_interfaces` ×2 (Jinja), `present` ×1 | 7 | moyenne |
| `pfsense_dns` | `present`, `absent` | 2 | moyenne |
| `pfsense_vlan` | `present`, `absent` | 2 | moyenne |
| `pfsense_dhcp_static_map` | `present`, `apply` | 2 | moyenne |
| `pfsense_ssh_auth` | `present`, `absent` | 2 | moyenne |
| `pfsense_gateway` | `list_gateways` (Jinja) | 1 | basse |
| `pfsense_nat_rule` | `present` | 1 | basse |
| `pfsense_user_cert` | `present` | 1 | moyenne |
| `pfsense_dhcp_kea` | `migrated` | 1 | haute (chantier Kea) |
| `pfsense_sshguard_whitelist` | `present` | 1 | basse |
| `pfsense_althostname` | `present` | 1 | basse |
| `pfsense_zabbix_configuration` | `present` | 1 | basse |
| `pfsense_sudo_configuration` | `present` | 1 | basse |
| `pfsense_certificate`, `pfsense_openvpn` | exécution directe (outil VPN) | 0 | haute (usage quotidien) |
| `pfsense_be` | aucune (les outils appellent le helper directement) | 0 | basse |
| `pfsense_wireguard`, `pfsense_webgui_settings`, `pfsense_if_pppoe` | aucune | 0 | basse |
| `pfsense_config` | exécution directe (MCP, lecture) | 0 | lecture seule, hors API |

## Code mort et incohérences confirmés

- **`_utils/pfsense.py`.** Méthodes FauxAPI jamais appelées : `config_reload`, `config_backup`, `config_backup_list`, `config_restore`, `system_reboot`, `system_stats`, `gateway_status`, `rule_get`, `alias_update_urltables`.
- **`helpers/crl_unrevoke.php`.** Appelé nulle part.
- **`helpers/nat_rule.php`.** Stub vide (`exit(0)`), jamais appelé.
- **`helpers/resolvconf.php` et `helpers-244RELEASE/resolvconf.php`.** Jamais appelés : `pfsense_dns` utilise `/etc/rc.resolv_conf_generate`.
- **`helpers/pkg_manager.php`.** Pas de code mort : aucun module ne l'appelle, mais les outils de maintenance s'en servent. Il est conservé.
- **`_states/pfsense_user_cert.revoked`.** Sort avant toute logique.
- **`_modules/pfsense_be.py`.** Il appelle `/scripts/manage_bootenv.php`, alors que le helper n'est déployé que dans `/opt/helpers` : le module ne peut pas fonctionner tel quel. À corriger au lot 1 (T1.7).

## Conséquences pour le plan

- **Priorités du lot 4.** La plus haute va à alias, syslog, filter_rule, user et au couple certificate/openvpn (outil VPN).
- **Signatures publiques à conserver.** Elles sont utilisées en exécution directe par l'outil VPN : `pfsense_user.export_openvpn_config` et `pfsense_certificate.add_user_certificate`.
- **`pfsense_interface.list_wan_interfaces` et `list_lan_interfaces`.** Ils sont appelés depuis Jinja au rendu : ils doivent rester rapides et sans effet de bord.

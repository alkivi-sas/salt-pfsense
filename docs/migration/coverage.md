# Matrice de couverture pfrest (T0.4)

Relevé du 2026-10-19 sur les trois versions de pfSense-pkg-RESTAPI à épingler. Une version est retenue par branche de pfSense ; voir [`versions.md`](versions.md).

**Sources par version :**
- **v2.10.2 :** `openapi.json` publié avec la release ; 267 endpoints.
- **v2.7.7 :** pas de schéma publié (404). Lecture des classes PHP du paquet de la release (`pfSense-2.8.1-pkg-RESTAPI.pkg`) ; 258 endpoints.
- **v2.4.3 :** pas de schéma publié. Lecture des classes PHP de `pfSense-24.03-pkg-RESTAPI.pkg` ; 212 endpoints.

Pour valider la méthode, le même parsing PHP appliqué au paquet v2.10.2 redonne exactement l'OpenAPI publié : mêmes 267 chemins, mêmes méthodes, mêmes propriétés. Un seul paquet a été lu par version : un build destiné à une autre branche de pfSense pourrait différer légèrement (non vérifié).

## 1. Endpoints utilisés, par version

Notation : ✓ = présent avec les mêmes méthodes que v2.10.2 ; ✗ = absent.

| Endpoint | v2.10.2 | v2.7.7 | v2.4.3 | Modules concernés |
|---|---|---|---|---|
| `firewall/rule` (GET POST PATCH DELETE) | ✓ | ✓ | ✓ | filter_rule |
| `firewall/alias` | ✓ | ✓ | ✓ | alias |
| `firewall/apply` (GET POST) | ✓ | ✓ | ✓ | alias, filter_rule, nat_rule |
| `firewall/nat/port_forward` | ✓ | ✓ | ✓ | nat_rule |
| `interface`, `interface/vlan`, `interface/apply` | ✓ | ✓ | ✓ | interface, vlan |
| `routing/gateway`, `routing/apply`, `status/gateways` | ✓ | ✓ | ✓ | gateway, dns |
| `services/dhcp_server` | ✓ | ✓ | GET PATCH seulement | dhcp_static_map, dhcp_kea |
| `services/dhcp_server/static_mapping` | ✓ | ✓ | ✓ | dhcp_static_map |
| `services/dhcp_server/custom_option` | ✓ | ✓ | ✓ | dhcp_kea |
| `services/dhcp_server/backend` (PATCH) | ✓ | ✓ | ✓ | dhcp_kea |
| `services/dhcp_server/apply` | ✓ | ✓ | ✓ | dhcp_static_map, dhcp_kea |
| `services/cron/job` | ✓ | ✓ | ✓ | cron |
| `system/dns` | ✓ | ✓ | ✓ | dns |
| `status/logs/settings` | ✓ | ✓ | ✓ | syslog_configuration |
| `system/webgui/settings` | ✓ | ✓ | ✓ | webgui_settings |
| `services/ssh`, `system/hostname` | ✓ | ✓ | ✓ | — |
| `user`, `user/group` | ✓ | ✓ | ✓ | user, ssh |
| `system/certificate`, `…/generate`, `system/certificate_authority` | ✓ | ✓ | ✓ | certificate |
| `system/crl`, `system/crl/revoked_certificate` | ✓ | ✓ | ✓ | certificate |
| `vpn/openvpn/server` | ✓ | ✓ | ✓ | openvpn |
| `vpn/openvpn/client_export` (POST) | ✓ | ✓ | **✗** | user (export) |
| `vpn/wireguard/tunnel`, `…/peer`, `…/apply` | ✓ | ✓ | ✓ | wireguard |
| `auth/key`, `system/restapi/settings`, `system/restapi/access_list/entry` | ✓ | ✓ | ✓ | lot 3 |
| `system/package` | ✓ | ✓ | ✓ | lot 3 (paquets dépendants) |
| `diagnostics/config_history/revision(s)` | ✓ | ✓ | ✓ | lot 2 (détection de conflit) |
| `system/version` | ✓ | ✓ | ✓ | lot 3 |
| `diagnostics/command_prompt` | ✓ | ✓ | ✓ | **interdit** (privilège jamais accordé) |

Endpoints au pluriel absents en v2.4.3 : `services/dhcp_server/static_mappings`, `services/dhcp_server/custom_options`. Ils ne sont pas nécessaires : le plan interdit les PUT au pluriel.

## 2. Mode test (`dry_run`)

| Version | Prise en charge |
|---|---|
| v2.10.2 | Oui, sur toutes les écritures (POST, PUT, PATCH, DELETE) : champ `dry_run` dans le corps, ou en-tête `Prefer: dry-run`. La requête est validée, mais rien n'est écrit ni appliqué. Le paramètre n'apparaît pas dans le schéma OpenAPI, bien qu'il soit implémenté (`Core/Endpoint.inc`, `validate_dry_run()`). Sur un GET, il est refusé (`ENDPOINT_DRY_RUN_NOT_SUPPORTED_ON_GET`). |
| v2.7.7, v2.4.3 | Non. Seuls `SystemReboot` et `SystemHalt` ont un champ `dry_run` propre. |

Conséquence : sur v2.7.7 et v2.4.3, le mode test Salt doit être calculé côté client, en comparant l'état lu à l'état voulu, sans validation serveur. C'est une entrée pour V6 : la couche d'adaptation doit traiter cette différence.

## 3. Différences de champs entre versions

Comparaison des noms de champs, sans comparer les types ni les valeurs admises :
- **`FirewallRule`.** `dscp` n'existe qu'en v2.10.2.
- **`DHCPServer`.** v2.10.2 ajoute les champs de démarrage réseau : `netboot`, `nextserver`, `filename*`, `uefihttpboot`, `rootpath`.
- **Aucune différence** pour `PortForward`, `User`, `DHCPServerStaticMapping`, `WireGuardPeer`, `OpenVPNServer` et `LogSettings`.

## 4. DHCP et Kea

- **Options personnalisées.** L'endpoint `services/dhcp_server/custom_option` existe dans les trois versions. Il s'appuie sur le modèle `DHCPServerCustomOption` (champs `number`, `type`, `value`), avec pour parent `DHCPServer` et pour chemin de config `numberoptions/item`. Il couvre la lecture et la suppression des options ISC.
- **Backend.** `services/dhcp_server/backend` choisit le serveur via le champ `dhcpbackend`, qui vaut `isc` (par défaut) ou `kea`.
- **Configuration JSON Kea personnalisée** (`kea.custom_kea_config`, `dhcpd.<if>.custom_kea_config`). Elle n'est **exposée dans aucune version** et aucun champ propre à Kea n'existe dans `DHCPServer`. Elle passe donc par le helper générique du lot 5 (`config_path`), ce qui confirme l'hypothèse de 4.4b dans le plan.

## 5. Synthèse par module

| Module | Couverture | Mécanisme |
|---|---|---|
| alias, filter_rule, nat_rule, vlan, interface, gateway, cron, syslog_configuration, user, ssh, certificate, openvpn (lecture), wireguard, dhcp_static_map | native, 3 versions | endpoints ci-dessus |
| user (export OpenVPN) | native en v2.10.2 et v2.7.7 | helper `export_openvpn_config.php` conservé pour v2.4.3 |
| dns | native pour les serveurs ; passerelles par serveur (`dnsNgw`) non exposées | `system/dns` + `config_path` |
| webgui_settings | partielle (`protocol`, `port`, `sslcertref`) | `system/webgui/settings` + `config_path` |
| dhcp_kea | backend et options ISC natifs, JSON Kea non exposé | endpoints + `config_path` |
| althostname, sshguard_whitelist, if_pppoe, sudo_configuration, zabbix_configuration | aucune | `config_path` (lot 5) |
| be | aucune | helper `manage_bootenv.php` conservé |
| config | lecture locale de `config.xml` | hors API (T2.8) |

## Sources

- https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/download/v2.10.2/openapi.json
- https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/download/v2.10.2/native.json
- https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/download/v2.10.2/pfSense-2.8.1-pkg-RESTAPI.pkg
- https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/download/v2.7.7/pfSense-2.8.1-pkg-RESTAPI.pkg
- https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/download/v2.4.3/pfSense-24.03-pkg-RESTAPI.pkg
- https://api.github.com/repos/pfrest/pfSense-pkg-RESTAPI/releases/tags/v2.10.2 (et v2.7.7, v2.4.3) : liste des assets

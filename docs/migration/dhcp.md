# Inventaire DHCP (T0.6)

**Statut : en attente.** La lecture de la configuration DHCP du parc (`pfsense_config.get` via la gateway MCP) a été refusée le 2026-10-19 par le contrôle d'accès de la session d'automatisation. Il faut une autorisation explicite pour relever les champs ci-dessous. La méthode et la grille sont prêtes.

## Champs relevés par pare-feu

Tous en lecture seule, chemins `config.xml` :

| Donnée | Chemin | Usage |
|---|---|---|
| Backend | `dhcpbackend` | `isc` (absent) ou `kea` |
| Interfaces DHCP actives | `dhcpd:<if>:enable` | périmètre de migration |
| Options personnalisées | `dhcpd:<if>:numberoptions:item:*:number` | numéros d'option seulement, sans les valeurs |
| Failover | `dhcpd:<if>:failover_peerip` | présence seulement |
| Static mappings | `dhcpd:<if>:staticmap` (taille via `tree`) | volume |
| JSON Kea personnalisé | `kea:custom_kea_config`, `dhcpd:<if>:custom_kea_config` | présence seulement |

Seules des présences, des numéros d'option et des tailles sont conservés : aucune adresse, aucun nom d'hôte, aucune valeur d'option.

## Grille de classement

| Classe | Condition |
|---|---|
| sans DHCP | aucune interface `dhcpd` active |
| déjà Kea | `dhcpbackend = kea` |
| migrable automatiquement | backend ISC, pas de failover, options toutes présentes dans le pillar `pfsense:dhcp_kea:options` |
| option à ajouter à la table | backend ISC, pas de failover, au moins une option hors table |
| manuel | failover configuré sur une interface |

## Résultats

À compléter. Pour chaque classe : nombre de pare-feux et liste `FW-NNN` (voir [`versions.md`](versions.md)). Ajouter aussi la liste des numéros d'option hors table, avec leur nombre d'occurrences.

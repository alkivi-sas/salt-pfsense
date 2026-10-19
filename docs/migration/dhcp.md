# Inventaire DHCP (T0.6)

Relevé du 2026-10-19 sur les 206 pare-feux de [`versions.md`](versions.md), en lecture seule via `pfsense_config` : 204 lus, 2 hors ligne. Seuls des présences, des numéros d'option et des comptes sont conservés : aucune adresse, aucun nom d'hôte, aucune valeur d'option.

## Champs relevés

| Donnée | Chemin `config.xml` |
|---|---|
| Backend | `dhcpbackend` (absent = `isc`) |
| Interfaces DHCP actives | `dhcpd:<if>:enable` |
| Options personnalisées (numéros) | `dhcpd:<if>:numberoptions:item:*:number`, interfaces actives seulement |
| Failover | `dhcpd:<if>:failover_peerip` (présence), interfaces actives seulement |
| JSON Kea global | `kea:custom_kea_config` (présence) |
| JSON Kea par interface | `dhcpd:<if>:custom_kea_config` (nombre d'interfaces actives) |
| Static mappings | `dhcpd:<if>:staticmap` (taille), interfaces actives seulement |

## Classement

La table d'options gérées est celle du pillar `pfsense:dhcp_kea:options`, qui contient deux entrées :
- 43 `unificontroller`, type binaire en hexadécimal ;
- 132 `yealink-vlan`, type chaîne, `always-send`.

| Classe | Pare-feux | Liste |
|---|---|---|
| déjà Kea | 121 | — (voir le détail) |
| migrable automatiquement (ISC, options 43 et 132 seulement, pas de failover) | 14 | FW-001, FW-015, FW-039, FW-042, FW-085, FW-095, FW-116, FW-124, FW-152, FW-153, FW-157, FW-183, FW-190, FW-194 |
| option à ajouter à la table | 3 | FW-031, FW-084, FW-184 (option 66) |
| manuel (failover ISC) | 9 | FW-148, FW-154, FW-155, FW-156, FW-180, FW-192 et leurs nœuds de secours FW-203, FW-205, FW-206 |
| sans DHCP (aucune interface active) | 10 | FW-026, FW-059, FW-088, FW-102, FW-114, FW-130, FW-133, FW-149, FW-187, FW-198 |
| hors périmètre (FreeBSD < 14 : pas de Kea) | 47 | voir [`versions.md`](versions.md) |
| hors ligne au relevé | 2 | FW-040, FW-204 (secours de FW-156, déjà classé manuel) |

## Constats

- **La migration Kea est déjà largement faite à la main.**
  - 121 pare-feux tournent sous Kea.
  - 108 d'entre eux portent le JSON Kea global et au moins un JSON par interface : c'est le schéma reproduit par `pfsense_dhcp_kea`.
  - Il en reste 26 à migrer dans le périmètre : 14 automatiquement, 3 après extension de la table, 9 à la main.
- **Option 66 (serveur TFTP).** Elle apparaît sur 3 pare-feux du périmètre, toujours aux côtés de 132.
  - Il faut l'ajouter au pillar `pfsense:dhcp_kea:options` : type chaîne, en général `always-send` pour les téléphones.
  - Avant cela, valider l'offre DHCP en lab (EXP-08).
- **Failover ISC.** Il est configuré sur 6 sites, dont 4 en paire CARP gérée.
  - Le failover ISC n'a pas d'équivalent direct : il faut passer au mode HA de Kea, configuré à la main (refus explicite de `pfsense_dhcp_kea.migrated`).
  - Un pare-feu déjà sous Kea a une paire HA avec failover déclaré : à examiner comme référence de la procédure manuelle.
- **Pare-feux hors périmètre.** Les options présentes sur les pare-feux hors périmètre ne sont pas prises en compte : ces pare-feux n'ont pas Kea. Par exemple, l'option 137 apparaît sur un seul d'entre eux.
- **Volume.** 4 708 static mappings au total, soit le volume à couvrir par les scénarios de 4.4 (lot 4).

## Conséquences pour le plan

- **T1.8.** Le scénario de lab doit couvrir les options 43, 132 et 66, avec une capture DHCP avant et après (EXP-08).
- **Recette 18b.** Ajouter la procédure manuelle de failover ISC → Kea HA, en s'appuyant sur le pare-feu déjà migré.
- **T7.3b.** 14 pare-feux en première vague, puis 3 après validation de l'option 66, puis 9 à la main.

## Détail par pare-feu

| Pare-feu | Backend | Interfaces actives | Options | Failover | JSON Kea global | JSON Kea interfaces | Static mappings | Classe |
|---|---|---|---|---|---|---|---|---|
| FW-001 | isc | 2 | 43,132 | no | no | 0 | 27 | migrable automatiquement |
| FW-002 | kea | 2 | - | no | yes | 1 | 12 | déjà Kea |
| FW-003 | kea | 2 | - | no | yes | 1 | 10 | déjà Kea |
| FW-004 | kea | 2 | - | no | yes | 1 | 13 | déjà Kea |
| FW-005 | kea | 3 | - | no | yes | 1 | 16 | déjà Kea |
| FW-006 | kea | 2 | - | no | yes | 1 | 13 | déjà Kea |
| FW-007 | kea | 2 | - | no | yes | 1 | 15 | déjà Kea |
| FW-008 | kea | 2 | - | no | yes | 1 | 18 | déjà Kea |
| FW-009 | kea | 3 | - | no | yes | 1 | 15 | déjà Kea |
| FW-010 | kea | 2 | - | no | yes | 1 | 16 | déjà Kea |
| FW-011 | kea | 2 | - | no | yes | 1 | 2 | déjà Kea |
| FW-012 | kea | 2 | - | no | yes | 1 | 10 | déjà Kea |
| FW-013 | kea | 2 | - | no | yes | 1 | 4 | déjà Kea |
| FW-014 | kea | 2 | - | no | yes | 1 | 2 | déjà Kea |
| FW-015 | isc | 2 | 43,132 | no | no | 0 | 6 | migrable automatiquement |
| FW-016 | kea | 2 | - | no | yes | 1 | 14 | déjà Kea |
| FW-017 | kea | 3 | - | no | yes | 1 | 30 | déjà Kea |
| FW-018 | kea | 2 | - | no | yes | 1 | 14 | déjà Kea |
| FW-019 | kea | 2 | - | no | yes | 1 | 14 | déjà Kea |
| FW-020 | isc | 2 | 43,132 | no | no | 0 | 5 | hors périmètre (FreeBSD < 14) |
| FW-021 | kea | 2 | - | no | yes | 1 | 6 | déjà Kea |
| FW-022 | isc | 2 | 132 | no | no | 0 | 8 | hors périmètre (FreeBSD < 14) |
| FW-023 | kea | 2 | - | no | yes | 1 | 6 | déjà Kea |
| FW-024 | kea | 2 | - | no | yes | 1 | 7 | déjà Kea |
| FW-025 | kea | 2 | - | no | yes | 1 | 3 | déjà Kea |
| FW-026 | kea | 0 | - | no | no | 0 | 0 | sans DHCP |
| FW-027 | isc | 2 | 43,132 | no | no | 0 | 15 | hors périmètre (FreeBSD < 14) |
| FW-028 | kea | 2 | - | no | yes | 1 | 5 | déjà Kea |
| FW-029 | kea | 2 | - | no | yes | 1 | 46 | déjà Kea |
| FW-030 | isc | 2 | 132 | no | no | 0 | 9 | hors périmètre (FreeBSD < 14) |
| FW-031 | isc | 2 | 66,132 | no | no | 0 | 23 | option à ajouter à la table |
| FW-032 | kea | 2 | - | no | yes | 1 | 7 | déjà Kea |
| FW-033 | kea | 2 | - | no | yes | 1 | 8 | déjà Kea |
| FW-034 | isc | 2 | 43,132 | no | no | 0 | 6 | hors périmètre (FreeBSD < 14) |
| FW-035 | isc | 2 | 132 | no | no | 0 | 14 | hors périmètre (FreeBSD < 14) |
| FW-036 | isc | 2 | 43,132 | no | no | 0 | 10 | hors périmètre (FreeBSD < 14) |
| FW-037 | kea | 2 | - | no | no | 0 | 13 | déjà Kea |
| FW-038 | kea | 3 | - | no | yes | 1 | 18 | déjà Kea |
| FW-039 | isc | 2 | 43,132 | no | no | 0 | 10 | migrable automatiquement |
| FW-040 | - | 0 | - | - | - | - | - | hors ligne |
| FW-041 | kea | 2 | - | no | yes | 1 | 4 | déjà Kea |
| FW-042 | isc | 2 | 43,132 | no | no | 0 | 7 | migrable automatiquement |
| FW-043 | kea | 2 | - | no | yes | 1 | 12 | déjà Kea |
| FW-044 | kea | 2 | - | no | yes | 1 | 27 | déjà Kea |
| FW-045 | kea | 3 | - | no | yes | 1 | 33 | déjà Kea |
| FW-046 | kea | 3 | - | no | yes | 1 | 20 | déjà Kea |
| FW-047 | kea | 3 | - | no | yes | 1 | 7 | déjà Kea |
| FW-048 | kea | 2 | - | no | yes | 1 | 11 | déjà Kea |
| FW-049 | kea | 9 | - | yes | yes | 3 | 61 | déjà Kea |
| FW-050 | kea | 2 | - | no | no | 0 | 11 | déjà Kea |
| FW-051 | kea | 2 | - | no | yes | 1 | 3 | déjà Kea |
| FW-052 | kea | 6 | - | no | yes | 1 | 53 | déjà Kea |
| FW-053 | kea | 2 | - | no | yes | 1 | 7 | déjà Kea |
| FW-054 | kea | 2 | - | no | yes | 1 | 20 | déjà Kea |
| FW-055 | isc | 4 | 43,132 | no | no | 0 | 18 | hors périmètre (FreeBSD < 14) |
| FW-056 | isc | 3 | 132 | no | no | 0 | 14 | hors périmètre (FreeBSD < 14) |
| FW-057 | kea | 4 | - | no | yes | 1 | 40 | déjà Kea |
| FW-058 | isc | 5 | 43 | no | no | 0 | 67 | hors périmètre (FreeBSD < 14) |
| FW-059 | kea | 0 | - | no | no | 0 | 0 | sans DHCP |
| FW-060 | kea | 3 | - | no | yes | 1 | 57 | déjà Kea |
| FW-061 | kea | 5 | - | no | yes | 1 | 43 | déjà Kea |
| FW-062 | kea | 3 | - | no | yes | 1 | 58 | déjà Kea |
| FW-063 | kea | 3 | - | no | yes | 1 | 41 | déjà Kea |
| FW-064 | kea | 3 | - | no | yes | 1 | 7 | déjà Kea |
| FW-065 | kea | 3 | - | no | yes | 1 | 37 | déjà Kea |
| FW-066 | kea | 1 | - | no | no | 0 | 1 | déjà Kea |
| FW-067 | isc | 3 | 43 | no | no | 0 | 15 | hors périmètre (FreeBSD < 14) |
| FW-068 | isc | 3 | 43,132 | no | no | 0 | 7 | hors périmètre (FreeBSD < 14) |
| FW-069 | kea | 4 | - | no | yes | 2 | 9 | déjà Kea |
| FW-070 | isc | 0 | - | no | no | 0 | 0 | hors périmètre (FreeBSD < 14) |
| FW-071 | isc | 3 | 43 | no | no | 0 | 8 | hors périmètre (FreeBSD < 14) |
| FW-072 | isc | 3 | 132 | no | no | 0 | 8 | hors périmètre (FreeBSD < 14) |
| FW-073 | kea | 4 | - | no | yes | 1 | 9 | déjà Kea |
| FW-074 | isc | 4 | 43 | no | no | 0 | 16 | hors périmètre (FreeBSD < 14) |
| FW-075 | isc | 4 | 43 | no | no | 0 | 15 | hors périmètre (FreeBSD < 14) |
| FW-076 | kea | 4 | - | no | yes | 1 | 11 | déjà Kea |
| FW-077 | kea | 5 | - | no | yes | 1 | 18 | déjà Kea |
| FW-078 | kea | 4 | - | no | no | 0 | 9 | déjà Kea |
| FW-079 | kea | 3 | - | no | yes | 1 | 30 | déjà Kea |
| FW-080 | kea | 3 | - | no | yes | 1 | 5 | déjà Kea |
| FW-081 | isc | 3 | 43 | no | no | 0 | 60 | hors périmètre (FreeBSD < 14) |
| FW-082 | kea | 3 | - | no | yes | 1 | 17 | déjà Kea |
| FW-083 | isc | 3 | 43,66,132 | no | no | 0 | 116 | hors périmètre (FreeBSD < 14) |
| FW-084 | isc | 2 | 43,66,132 | no | no | 0 | 45 | option à ajouter à la table |
| FW-085 | isc | 5 | 43,132 | no | no | 0 | 138 | migrable automatiquement |
| FW-086 | kea | 2 | - | no | yes | 1 | 35 | déjà Kea |
| FW-087 | kea | 3 | - | no | yes | 1 | 23 | déjà Kea |
| FW-088 | isc | 0 | - | no | no | 0 | 0 | sans DHCP |
| FW-089 | kea | 3 | - | no | yes | 1 | 179 | déjà Kea |
| FW-090 | kea | 2 | - | no | yes | 1 | 28 | déjà Kea |
| FW-091 | kea | 4 | - | no | yes | 0 | 47 | déjà Kea |
| FW-092 | kea | 2 | - | no | yes | 1 | 33 | déjà Kea |
| FW-093 | kea | 3 | - | no | no | 0 | 166 | déjà Kea |
| FW-094 | kea | 3 | - | no | no | 0 | 23 | déjà Kea |
| FW-095 | isc | 2 | - | no | no | 0 | 3 | migrable automatiquement |
| FW-096 | kea | 2 | - | no | yes | 1 | 7 | déjà Kea |
| FW-097 | kea | 2 | - | no | yes | 1 | 8 | déjà Kea |
| FW-098 | kea | 3 | - | no | yes | 1 | 28 | déjà Kea |
| FW-099 | kea | 4 | - | no | yes | 1 | 18 | déjà Kea |
| FW-100 | kea | 3 | - | no | yes | 1 | 18 | déjà Kea |
| FW-101 | kea | 2 | - | no | yes | 1 | 15 | déjà Kea |
| FW-102 | isc | 0 | - | no | no | 0 | 0 | sans DHCP |
| FW-103 | kea | 2 | - | no | yes | 1 | 12 | déjà Kea |
| FW-104 | kea | 2 | - | no | yes | 1 | 15 | déjà Kea |
| FW-105 | isc | 4 | 132 | no | no | 0 | 30 | hors périmètre (FreeBSD < 14) |
| FW-106 | kea | 2 | - | no | yes | 1 | 11 | déjà Kea |
| FW-107 | kea | 2 | - | no | yes | 1 | 25 | déjà Kea |
| FW-108 | kea | 2 | - | no | no | 0 | 9 | déjà Kea |
| FW-109 | kea | 3 | - | no | yes | 1 | 5 | déjà Kea |
| FW-110 | kea | 3 | - | no | yes | 1 | 21 | déjà Kea |
| FW-111 | kea | 1 | - | no | no | 0 | 0 | déjà Kea |
| FW-112 | kea | 2 | - | no | yes | 1 | 20 | déjà Kea |
| FW-113 | kea | 2 | - | no | yes | 1 | 7 | déjà Kea |
| FW-114 | kea | 0 | - | no | yes | 0 | 0 | sans DHCP |
| FW-115 | kea | 3 | - | no | yes | 1 | 5 | déjà Kea |
| FW-116 | isc | 1 | - | no | no | 0 | 1 | migrable automatiquement |
| FW-117 | isc | 4 | 43,132 | no | no | 0 | 110 | hors périmètre (FreeBSD < 14) |
| FW-118 | kea | 1 | - | no | no | 0 | 10 | déjà Kea |
| FW-119 | isc | 2 | 132 | no | no | 0 | 11 | hors périmètre (FreeBSD < 14) |
| FW-120 | isc | 0 | - | no | no | 0 | 0 | hors périmètre (FreeBSD < 14) |
| FW-121 | kea | 2 | - | no | yes | 1 | 68 | déjà Kea |
| FW-122 | isc | 2 | 43,132 | no | no | 0 | 14 | hors périmètre (FreeBSD < 14) |
| FW-123 | isc | 2 | 43,132 | no | no | 0 | 31 | hors périmètre (FreeBSD < 14) |
| FW-124 | isc | 2 | 43,132 | no | no | 0 | 8 | migrable automatiquement |
| FW-125 | kea | 2 | - | no | yes | 1 | 28 | déjà Kea |
| FW-126 | kea | 2 | - | no | yes | 1 | 12 | déjà Kea |
| FW-127 | kea | 2 | - | no | yes | 1 | 10 | déjà Kea |
| FW-128 | kea | 2 | - | no | yes | 2 | 15 | déjà Kea |
| FW-129 | isc | 2 | - | no | no | 0 | 17 | hors périmètre (FreeBSD < 14) |
| FW-130 | kea | 0 | - | no | no | 0 | 0 | sans DHCP |
| FW-131 | kea | 4 | 43 | no | yes | 1 | 44 | déjà Kea |
| FW-132 | kea | 3 | - | no | yes | 1 | 22 | déjà Kea |
| FW-133 | kea | 0 | - | no | no | 0 | 0 | sans DHCP |
| FW-134 | isc | 2 | 132 | no | no | 0 | 4 | hors périmètre (FreeBSD < 14) |
| FW-135 | isc | 5 | 132,137 | no | no | 0 | 31 | hors périmètre (FreeBSD < 14) |
| FW-136 | kea | 2 | - | no | yes | 1 | 4 | déjà Kea |
| FW-137 | kea | 3 | - | no | yes | 1 | 14 | déjà Kea |
| FW-138 | kea | 3 | - | no | yes | 1 | 21 | déjà Kea |
| FW-139 | isc | 2 | 43,132 | no | no | 0 | 13 | hors périmètre (FreeBSD < 14) |
| FW-140 | kea | 2 | - | no | yes | 1 | 9 | déjà Kea |
| FW-141 | kea | 2 | - | no | yes | 1 | 11 | déjà Kea |
| FW-142 | isc | 3 | 132 | no | no | 0 | 5 | hors périmètre (FreeBSD < 14) |
| FW-143 | isc | 3 | 132 | no | no | 0 | 6 | hors périmètre (FreeBSD < 14) |
| FW-144 | isc | 2 | - | no | no | 0 | 11 | hors périmètre (FreeBSD < 14) |
| FW-145 | isc | 2 | 43,132 | no | no | 0 | 4 | hors périmètre (FreeBSD < 14) |
| FW-146 | isc | 2 | - | no | no | 0 | 23 | hors périmètre (FreeBSD < 14) |
| FW-147 | kea | 3 | - | no | yes | 1 | 49 | déjà Kea |
| FW-148 | isc | 4 | 43,132 | yes | no | 0 | 71 | manuel (failover) |
| FW-149 | kea | 0 | - | no | yes | 0 | 0 | sans DHCP |
| FW-150 | isc | 6 | 43,132 | no | no | 0 | 60 | hors périmètre (FreeBSD < 14) |
| FW-151 | kea | 5 | - | no | no | 0 | 61 | déjà Kea |
| FW-152 | isc | 4 | 43,132 | no | no | 0 | 18 | migrable automatiquement |
| FW-153 | isc | 2 | - | no | no | 0 | 1 | migrable automatiquement |
| FW-154 | isc | 2 | 43 | yes | no | 0 | 52 | manuel (failover) |
| FW-155 | isc | 4 | 43,132 | yes | no | 0 | 56 | manuel (failover) |
| FW-156 | isc | 20 | 43,132 | yes | no | 0 | 201 | manuel (failover) |
| FW-157 | isc | 6 | 43,132 | no | no | 0 | 41 | migrable automatiquement |
| FW-158 | isc | 2 | 132 | no | no | 0 | 17 | hors périmètre (FreeBSD < 14) |
| FW-159 | isc | 2 | 132 | no | no | 0 | 17 | hors périmètre (FreeBSD < 14) |
| FW-160 | kea | 2 | - | no | yes | 1 | 36 | déjà Kea |
| FW-161 | kea | 2 | - | no | yes | 1 | 58 | déjà Kea |
| FW-162 | isc | 2 | - | no | no | 0 | 29 | hors périmètre (FreeBSD < 14) |
| FW-163 | isc | 1 | - | no | no | 0 | 19 | hors périmètre (FreeBSD < 14) |
| FW-164 | kea | 2 | - | no | no | 0 | 15 | déjà Kea |
| FW-165 | kea | 6 | - | no | yes | 1 | 34 | déjà Kea |
| FW-166 | kea | 2 | - | no | yes | 1 | 7 | déjà Kea |
| FW-167 | kea | 2 | - | no | yes | 1 | 6 | déjà Kea |
| FW-168 | kea | 2 | - | no | yes | 1 | 3 | déjà Kea |
| FW-169 | kea | 2 | - | no | yes | 1 | 3 | déjà Kea |
| FW-170 | kea | 2 | - | no | yes | 1 | 4 | déjà Kea |
| FW-171 | kea | 2 | - | no | yes | 1 | 2 | déjà Kea |
| FW-172 | kea | 2 | - | no | yes | 1 | 5 | déjà Kea |
| FW-173 | kea | 2 | - | no | yes | 1 | 7 | déjà Kea |
| FW-174 | kea | 2 | - | no | no | 0 | 26 | déjà Kea |
| FW-175 | isc | 2 | 132 | no | no | 0 | 10 | hors périmètre (FreeBSD < 14) |
| FW-176 | kea | 3 | - | no | yes | 1 | 6 | déjà Kea |
| FW-177 | kea | 2 | - | no | yes | 1 | 1 | déjà Kea |
| FW-178 | isc | 4 | 43,132 | no | no | 0 | 9 | hors périmètre (FreeBSD < 14) |
| FW-179 | isc | 3 | 132 | no | no | 0 | 8 | hors périmètre (FreeBSD < 14) |
| FW-180 | isc | 6 | 43,132 | yes | no | 0 | 100 | manuel (failover) |
| FW-181 | isc | 0 | - | no | no | 0 | 0 | hors périmètre (FreeBSD < 14) |
| FW-182 | isc | 0 | - | no | no | 0 | 0 | hors périmètre (FreeBSD < 14) |
| FW-183 | isc | 3 | 43,132 | no | no | 0 | 22 | migrable automatiquement |
| FW-184 | isc | 3 | 66,132 | no | no | 0 | 43 | option à ajouter à la table |
| FW-185 | isc | 2 | 66 | no | no | 0 | 14 | hors périmètre (FreeBSD < 14) |
| FW-186 | kea | 2 | - | no | yes | 1 | 0 | déjà Kea |
| FW-187 | isc | 0 | - | no | no | 0 | 0 | sans DHCP |
| FW-188 | isc | 2 | 43,132 | no | no | 0 | 23 | hors périmètre (FreeBSD < 14) |
| FW-189 | kea | 2 | - | no | yes | 1 | 12 | déjà Kea |
| FW-190 | isc | 3 | 43,132 | no | no | 0 | 19 | migrable automatiquement |
| FW-191 | kea | 4 | - | no | yes | 1 | 64 | déjà Kea |
| FW-192 | isc | 3 | 43,132 | yes | no | 0 | 44 | manuel (failover) |
| FW-193 | kea | 2 | - | no | yes | 1 | 4 | déjà Kea |
| FW-194 | isc | 12 | 43,132 | no | no | 0 | 61 | migrable automatiquement |
| FW-195 | isc | 2 | 66,132 | no | no | 0 | 22 | hors périmètre (FreeBSD < 14) |
| FW-196 | kea | 2 | - | no | yes | 1 | 6 | déjà Kea |
| FW-197 | kea | 4 | - | no | yes | 1 | 31 | déjà Kea |
| FW-198 | isc | 0 | - | no | no | 0 | 0 | sans DHCP |
| FW-199 | kea | 11 | - | no | yes | 1 | 12 | déjà Kea |
| FW-200 | kea | 2 | - | no | yes | 1 | 6 | déjà Kea |
| FW-201 | kea | 3 | - | no | yes | 1 | 19 | déjà Kea |
| FW-202 | kea | 9 | - | yes | yes | 3 | 61 | déjà Kea |
| FW-203 | isc | 4 | 43,132 | yes | no | 0 | 56 | manuel (failover) |
| FW-204 | - | 0 | - | - | - | - | - | hors ligne |
| FW-205 | isc | 6 | 43,132 | yes | no | 0 | 100 | manuel (failover) |
| FW-206 | isc | 3 | 43,132 | yes | no | 0 | 44 | manuel (failover) |

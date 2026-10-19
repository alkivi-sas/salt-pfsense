# Matrice de versions du parc (T0.1)

Relevé du 2026-10-19 via les grains Salt (`version`, `cpuarch`), sur 206 pare-feux : 201 nœuds principaux et 5 nœuds de secours CARP. Les pare-feux sont anonymisés (`FW-NNN`) ; la correspondance avec les équipements est tenue hors dépôt. Deux équipements hors ligne ont été lus depuis le cache des grains. Les bases FreeBSD viennent de https://docs.netgate.com/pfsense/en/latest/releases/versions.html.

## Périmètre

Le projet ne supporte que les versions de pfSense basées sur **FreeBSD 14, 15 ou 16** :
- CE : 2.7.x, 2.8.x, 2.9.x ;
- Plus : 23.01 et suivantes.

Les versions plus anciennes sont hors périmètre. Elles restent sur la couche actuelle, sans évolution.

## Synthèse

| Édition | Version | FreeBSD | Pare-feux | Version pfrest cible |
|---|---|---|---|---|
| Plus | 26.07 | 16.0 | 135 | v2.10.2 (dont 6 en armv7, à valider) |
| Plus | 26.03.1 | 16.0 | 7 | v2.10.2 |
| Plus | 26.03 | 16.0 | 2 | v2.10.2 |
| Plus | 25.11 | 16.0 | 1 | v2.7.7, ou v2.10.2 après passage en 25.11.1+ |
| CE | 2.9.0 | 16.0 | 1 | v2.10.2 |
| CE | 2.8.1 | 15.0 | 7 | v2.10.2 |
| CE | 2.7.2 | 14.0 | 5 | v2.4.3 |
| CE | 2.7.0 | 14.0 | 1 | aucune v2 |
| CE | 2.6.0 | 12.3 | 7 | hors périmètre |
| CE | 2.5.0 / 2.5.1 / 2.5.2 | 12.2 | 2 / 1 / 6 | hors périmètre |
| CE | 2.4.5 | 11.3 | 11 | hors périmètre |
| CE | 2.4.4 | 11.2 | 20 | hors périmètre |

| Cible | Pare-feux |
|---|---|
| Dans le périmètre (FreeBSD ≥ 14) | **159** |
| — v2.10.2 directement | 146 |
| — v2.10.2, armv7 32 bits à valider | 6 |
| — mise à jour de pfSense préalable (CE 2.7.0, CE 2.7.2, Plus 25.11) | 7 |
| Hors périmètre (FreeBSD < 14) | 47 |

**Matériel et architecture.**
- **Boîtiers Netgate.** Ils sont presque tous en Plus 26.07.
- **Architectures dans le périmètre.** 102 arm64, 51 amd64 et 6 armv7.
- **Paquet pfrest.** La v2.10.2 déclare l'ABI `FreeBSD:15:*` : elle ne dépend pas de l'architecture.
- **À valider en lab.** Le fonctionnement sur arm64 (102 pare-feux) et sur armv7, que pfrest ne supporte pas officiellement.

## Décision proposée

- **Une seule version pfrest épinglée : v2.10.2.** C'est la seule qui a le `dry_run` (voir [`coverage.md`](coverage.md)), et elle couvre 152 des 159 pare-feux du périmètre.
- **Les 7 autres pare-feux du périmètre** passent d'abord à une version couverte par v2.10.2, plutôt que de maintenir v2.4.3 et v2.7.7 :
  - CE 2.7.0 et CE 2.7.2 (6 pare-feux, dont un nœud de secours) → CE 2.8.1 ou 2.9.0 ;
  - Plus 25.11 (1 pare-feu) → Plus 26.07.
- **armv7 (6 pare-feux en Plus 26.07).** Test en lab ; en cas d'échec, ils restent sur la couche actuelle jusqu'au remplacement du matériel.
- **Hors périmètre (47 pare-feux).** Aucun travail : ils restent sur FauxAPI. Aucun backend pfrest v1 n'est développé.

Avec ces choix, la matrice de V6 se réduit à **une version pfrest** et trois bases : CE 2.8.1 (FreeBSD 15), CE 2.9.0 et Plus 25.11.1 à 26.07 (FreeBSD 16). Le lab (T1.3) doit couvrir CE 2.8.1, CE 2.9.0 et Plus 26.07, en amd64, arm64 et armv7.

## Détail par pare-feu

| Pare-feu | Édition | Version | FreeBSD | Arch. | Cible pfrest | Remarque | Source |
|---|---|---|---|---|---|---|---|
| FW-001 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-002 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-003 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-004 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-005 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-006 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-007 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-008 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-009 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-010 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-011 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-012 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-013 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-014 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-015 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-016 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-017 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-018 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-019 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-020 | CE | 2.5.2 | 12.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-021 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-022 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-023 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-024 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-025 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-026 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-027 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-028 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-029 | Plus | 26.07 | 16.0 | arm | v2.10.2 à valider (armv7 32 bits non supporté officiellement) |  | grains |
| FW-030 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-031 | Plus | 26.07 | 16.0 | arm | v2.10.2 à valider (armv7 32 bits non supporté officiellement) |  | grains |
| FW-032 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-033 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-034 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-035 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-036 | CE | 2.6.0 | 12.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-037 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-038 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-039 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-040 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | cache |
| FW-041 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-042 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-043 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-044 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-045 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-046 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-047 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-048 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-049 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-050 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-051 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-052 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-053 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-054 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-055 | CE | 2.5.0 | 12.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-056 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-057 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-058 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-059 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-060 | Plus | 26.07 | 16.0 | arm | v2.10.2 à valider (armv7 32 bits non supporté officiellement) |  | grains |
| FW-061 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-062 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-063 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-064 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-065 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-066 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-067 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-068 | CE | 2.5.2 | 12.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-069 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-070 | CE | 2.6.0 | 12.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-071 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-072 | CE | 2.5.0 | 12.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-073 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-074 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-075 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-076 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-077 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | cache |
| FW-078 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-079 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-080 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-081 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-082 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-083 | CE | 2.5.2 | 12.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-084 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-085 | CE | 2.8.1 | 15.0 | amd64 | v2.10.2 |  | grains |
| FW-086 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-087 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-088 | CE | 2.8.1 | 15.0 | amd64 | v2.10.2 |  | grains |
| FW-089 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-090 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-091 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-092 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-093 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-094 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-095 | CE | 2.9.0 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-096 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-097 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-098 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-099 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-100 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-101 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-102 | CE | 2.7.2 | 14.0 | amd64 | v2.4.3 |  | grains |
| FW-103 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-104 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-105 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-106 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-107 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-108 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-109 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-110 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-111 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-112 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-113 | Plus | 26.07 | 16.0 | arm | v2.10.2 à valider (armv7 32 bits non supporté officiellement) |  | grains |
| FW-114 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-115 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-116 | Plus | 25.11 | 16.0 | amd64 | v2.7.7 |  | grains |
| FW-117 | CE | 2.5.2 | 12.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-118 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-119 | CE | 2.6.0 | 12.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-120 | CE | 2.6.0 | 12.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-121 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-122 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-123 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-124 | CE | 2.8.1 | 15.0 | amd64 | v2.10.2 |  | grains |
| FW-125 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-126 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-127 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-128 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-129 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-130 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-131 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-132 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-133 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-134 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-135 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-136 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-137 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-138 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-139 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-140 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-141 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-142 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-143 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-144 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-145 | CE | 2.5.2 | 12.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-146 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-147 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-148 | CE | 2.7.0 | 14.0 | amd64 | aucune v2 (upgrade pfSense requis) |  | grains |
| FW-149 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-150 | CE | 2.5.2 | 12.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-151 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-152 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-153 | Plus | 26.03.1 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-154 | Plus | 26.03.1 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-155 | Plus | 26.03.1 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-156 | Plus | 26.03.1 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-157 | Plus | 26.03.1 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-158 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-159 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-160 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-161 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-162 | CE | 2.4.5 | 11.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-163 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-164 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-165 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-166 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-167 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-168 | Plus | 26.07 | 16.0 | arm | v2.10.2 à valider (armv7 32 bits non supporté officiellement) |  | grains |
| FW-169 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-170 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-171 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-172 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-173 | Plus | 26.07 | 16.0 | arm | v2.10.2 à valider (armv7 32 bits non supporté officiellement) |  | grains |
| FW-174 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-175 | CE | 2.6.0 | 12.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-176 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-177 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-178 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-179 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-180 | CE | 2.7.2 | 14.0 | amd64 | v2.4.3 |  | grains |
| FW-181 | CE | 2.6.0 | 12.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-182 | CE | 2.6.0 | 12.3 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-183 | CE | 2.8.1 | 15.0 | amd64 | v2.10.2 |  | grains |
| FW-184 | CE | 2.7.2 | 14.0 | amd64 | v2.4.3 |  | grains |
| FW-185 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-186 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-187 | CE | 2.7.2 | 14.0 | amd64 | v2.4.3 |  | grains |
| FW-188 | CE | 2.4.4 | 11.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-189 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-190 | CE | 2.8.1 | 15.0 | amd64 | v2.10.2 |  | grains |
| FW-191 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-192 | Plus | 26.03 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-193 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-194 | CE | 2.8.1 | 15.0 | amd64 | v2.10.2 |  | grains |
| FW-195 | CE | 2.5.1 | 12.2 | amd64 | hors périmètre (FreeBSD < 14) |  | grains |
| FW-196 | Plus | 26.07 | 16.0 | arm64 | v2.10.2 |  | grains |
| FW-197 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-198 | CE | 2.8.1 | 15.0 | amd64 | v2.10.2 |  | grains |
| FW-199 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-200 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-201 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 |  | grains |
| FW-202 | Plus | 26.07 | 16.0 | amd64 | v2.10.2 | secours de FW-049 | grains |
| FW-203 | Plus | 26.03.1 | 16.0 | amd64 | v2.10.2 | secours de FW-155 | grains |
| FW-204 | Plus | 26.03.1 | 16.0 | amd64 | v2.10.2 | secours de FW-156 | grains |
| FW-205 | CE | 2.7.2 | 14.0 | amd64 | v2.4.3 | secours de FW-180 | grains |
| FW-206 | Plus | 26.03 | 16.0 | arm64 | v2.10.2 | secours de FW-192 | grains |

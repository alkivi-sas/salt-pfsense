# Déploiement progressif (lot 7)

Plan d'exécution du passage du parc sur le backend pfrest. Il n'est **pas exécuté par ce dépôt** : chaque étape est lancée et validée par un administrateur, avec les recettes de [`../recipes/`](../recipes/README.md). Les pare-feux sont désignés par leur identifiant anonyme ([`versions.md`](versions.md)).

## Prérequis, une fois

1. Les PR des lots 1 à 6 sont mergées dans l'ordre ; le submodule est à jour dans le dépôt de states.
2. Recette 02 : `saltutil.sync_all` sur le parc. Ce déploiement n'a aucun effet tant que `pfsense:api_backend` vaut `fauxapi`.
3. Recette 03 : déployer les nouveaux helpers (`config_path.php`, `restapi_bootstrap.php`, `user_set_fields.php`).
4. Recette 04 : une clé API par pare-feu dans le pillar chiffré.
5. Mesures de référence sur le backend FauxAPI : durée du highstate et nombre de rechargements pf. Ce sont les indicateurs « avant ».

## Pilote : 1 pare-feu, observation 7 jours

**FW-026** : Plus 26.07, amd64, hébergé, sans DHCP actif. Il est choisi pour son exposition minimale.

1. Recette 05 (installer et amorcer pfrest), puis recette 06 module par module, dans l'ordre du lot 4 : alias, syslog, filter_rule, nat_rule, user, ssh, cron, vlan, dhcp_static_map, dns, interface, certificate, openvpn, wireguard, puis les modules du lot 5.
2. Pour chaque module :
   - `state.highstate test=True` : aucun changement attendu ;
   - passage réel ;
   - second passage à zéro changement.
3. Comparer `config.xml` avant et après chaque module avec `tests/oracle/diff_config.py` ; chaque écart est expliqué dans `tests/oracle/accepted_diffs.yaml`.
4. Observer 7 jours : supervision, journaux pfrest, accès VPN.

**Critère de passage :**
- aucun écart non expliqué ;
- aucun incident attribuable ;
- highstate quotidien à zéro changement.

## Vagues

| Vague | Pare-feux | Composition | Observation |
|---|---|---|---|
| 1 | 37 | amd64 hors paires HA : FW-017, FW-043, FW-059, FW-066, FW-085, FW-087 à FW-093, FW-095, FW-114, FW-121, FW-124, FW-130, FW-131, FW-133, FW-149, FW-151 à FW-154, FW-157, FW-161, FW-165, FW-183, FW-186, FW-190, FW-191, FW-194, FW-197 à FW-201 | 3 jours |
| 2 | 100 | arm64 hors paires HA, voir la liste ci-dessous | 3 jours |
| 3 | 8 | paires HA : FW-049/FW-202, FW-155/FW-203, FW-156/FW-204, FW-192/FW-206 | 3 jours |

Vague 2 : FW-001, FW-002, FW-003, FW-004, FW-005, FW-006, FW-007, FW-008, FW-009, FW-010, FW-011, FW-012, FW-013, FW-014, FW-015, FW-016, FW-018, FW-019, FW-021, FW-023, FW-024, FW-025, FW-028, FW-032, FW-033, FW-037, FW-038, FW-039, FW-040, FW-041, FW-042, FW-044, FW-045, FW-046, FW-047, FW-048, FW-050, FW-051, FW-052, FW-053, FW-054, FW-057, FW-061, FW-062, FW-063, FW-064, FW-065, FW-069, FW-073, FW-076, FW-077, FW-078, FW-079, FW-080, FW-082, FW-084, FW-086, FW-094, FW-096, FW-097, FW-098, FW-099, FW-100, FW-101, FW-103, FW-104, FW-106, FW-107, FW-108, FW-109, FW-110, FW-111, FW-112, FW-115, FW-118, FW-125, FW-126, FW-127, FW-128, FW-132, FW-136, FW-137, FW-138, FW-140, FW-141, FW-147, FW-160, FW-164, FW-166, FW-167, FW-169, FW-170, FW-171, FW-172, FW-174, FW-176, FW-177, FW-189, FW-193, FW-196.

Chaque vague passe par la recette 40 : `test=True` d'abord, puis `batch: 10%`, avec `failhard`. Les paires HA suivent la recette 41, nœud par nœud.

**Critère de passage d'une vague à la suivante :**
- 100 % de la vague à zéro changement au second passage ;
- aucun retour arrière ;
- aucun écart `config.xml` non expliqué sur un échantillon de 5 pare-feux.

## Cas particuliers

- **armv7 (6 pare-feux : FW-029, FW-031, FW-060, FW-113, FW-168, FW-173).** pfrest ne les supporte pas officiellement.
  - Tester d'abord sur l'un d'eux : recette 05, puis `pfsense_restapi.status` et un module en lecture.
  - En cas d'échec, ils restent sur FauxAPI (`api_backend: fauxapi`) jusqu'au remplacement du matériel.
- **Mise à jour de pfSense préalable (7 pare-feux : FW-102, FW-116, FW-148, FW-180, FW-184, FW-187, FW-205).** Ils sont en CE 2.7.x ou Plus 25.11.
  - Les passer en CE 2.8.1/2.9.0 ou Plus 26.07, dans une fenêtre de maintenance, puis les intégrer à la vague correspondante.
  - FW-180/FW-205 forment une paire HA : les traiter ensemble.
- **Hors périmètre (47 pare-feux, FreeBSD < 14).** Aucun changement : ils restent sur FauxAPI.

## Migration DHCP vers Kea (T7.3b)

Elle est indépendante de la bascule pfrest. Elle suit la recette 18b et le classement de [`dhcp.md`](dhcp.md).

| Étape | Pare-feux | Condition |
|---|---|---|
| 1 | 14 « migrables automatiquement » | capture DHCP avant et après sur le premier |
| 2 | 3 avec l'option 66 | après validation de l'option 66 sur Kea (EXP-08) et ajout à la table du pillar |
| 3 | 9 en failover ISC (6 sites) | migration manuelle vers Kea HA, nœud de secours d'abord |

## Indicateurs à relever par vague (T7.5)

| Indicateur | Mesure |
|---|---|
| Idempotence | part des pare-feux à zéro changement au second highstate |
| Durée | durée du highstate (`salt-run jobs.lookup_jid`), avant et après |
| Rechargements | nombre de `filter reload` et de `firewall/apply` par run (journaux système et pfrest) |
| Équivalence | écarts `config.xml` hors registre sur l'échantillon |
| Incidents | retours arrière, tickets attribuables |
| Sécurité | aucun secret dans `salt-call -l debug` (contrôle sur un pare-feu par vague) |

Les résultats sont consignés dans [`journal-deploiement.md`](journal-deploiement.md) et repris dans `docs/rd/06-resultats.md`.

## Retour arrière

Recette 44 : `pfsense:api_backend: fauxapi` sur le pare-feu ou la vague, puis `saltutil.refresh_pillar`. FauxAPI reste installé jusqu'au lot 8.

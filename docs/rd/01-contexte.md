# Contexte

## Problème

Un ensemble d'extensions SaltStack pilote de façon déclarative la configuration d'un parc de plusieurs centaines de pare-feux pfSense. Volume : environ 9 700 lignes, dont 23 modules d'exécution, 16 states et une dizaine de helpers PHP. Le périmètre couvre le filtrage, le NAT, les alias, les utilisateurs, la PKI, les VPN, le DHCP, les VLAN, le DNS, la journalisation et le cron.

Toute la couche d'accès à la configuration repose sur FauxAPI. Ce projet tiers est archivé ; sa dernière version date de 2020 et a été testée jusqu'à pfSense 2.4.5. Il expose la configuration brute (`config.xml`) en lecture et en écriture, sans validation métier.

## Défauts constatés de l'existant

- **Écritures massives.** Chaque modification réécrit une section entière de `config.xml`, voire le fichier entier. Une même opération en relit le contenu complet 3 à 6 fois.
- **Pas de garantie de cohérence.** Rien ne garantit l'atomicité ni la cohérence entre l'écriture et l'application. L'application des changements passe selon les modules par cinq mécanismes différents, ou n'existe pas.
- **States incomplets.** Le mode test de Salt (`test=True`) est cassé dans 4 states, deux states ne savent pas mettre à jour un objet existant, et un state n'est jamais idempotent.
- **Aucun test automatisé.**

## Enjeux

- **Risque opérationnel.** Chaque mise à jour de pfSense peut rompre l'accès à la configuration de tout le parc.
- **Sécurité.** Aujourd'hui, l'accès à l'API donne l'écriture totale sur `config.xml` ; la cible est un accès limité aux seuls objets nécessaires.
- **Fiabilité.** Il faut une idempotence vérifiable et un mode test réel avant tout changement sur le parc.

## Objectifs mesurables

| Objectif | Indicateur | Cible |
|---|---|---|
| Couverture fonctionnelle | part des fonctions publiques servies par la nouvelle couche | 100 % (natif, helper générique ou dédié) |
| Idempotence | changements au second passage | 0 sur 100 % des scénarios |
| Mode test | states renvoyant un diff réel en `test=True` | 100 % |
| Équivalence | écarts de `config.xml` hors registre entre ancienne et nouvelle implémentation | 0 |
| Sûreté | écritures sur un mauvais objet | 0 sur 1 000 itérations |
| Robustesse | cycle mise à jour pfSense → réinstallation → application sans intervention | 100 % des versions supportées |
| Sécurité | secret présent dans les journaux ou sorties | 0 |

## Périmètre

Inclus :
- la couche d'accès ;
- la migration de chaque module ;
- la migration DHCP ISC → Kea ;
- le cycle de vie du paquet d'API ;
- les recettes de déploiement ;
- le déploiement progressif sur le parc.

Exclu : l'évolution fonctionnelle des modules au-delà de ce que la migration impose.

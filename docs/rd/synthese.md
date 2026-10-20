# Synthèse des travaux

Migration d'une couche de gestion déclarative de pare-feux pfSense, de FauxAPI vers pfSense REST API v2. État au 2026-10-20.

## 1. Objet

Une couche de gestion SaltStack pilote la configuration d'un parc de 206 pare-feux pfSense. Elle reposait sur FauxAPI, un projet archivé, avec des écritures brutes de `config.xml`, sans validation et sans garantie de cohérence ([`01-contexte.md`](01-contexte.md)).

Les travaux visent à adosser cette couche à une API maintenue et validée, sans changer son contrat public, en levant les verrous qui empêchent de le faire de façon sûre sur un parc hétérogène.

## 2. État de l'art et limites

Les solutions existantes, détaillées dans [`02-etat-de-l-art.md`](02-etat-de-l-art.md), sont FauxAPI, pfrest v1 et v2, la collection Ansible pfrest et l'édition directe de `config.xml`. Aucune ne fournit à la fois :
- une identité stable des objets ;
- des écritures sûres en concurrence ;
- un mode test réel ;
- des privilèges minimaux ;
- une couverture complète ;
- un amorçage automatique.

## 3. Verrous

Huit verrous ont été identifiés et formalisés, chacun avec hypothèse, protocole et critère de levée ([`03-verrous.md`](03-verrous.md)).

## 4. Démarche

La démarche est décrite dans [`04-demarche.md`](04-demarche.md). Le banc d'équipements prévu n'a pas été disponible. La démarche a donc été adaptée en un **banc logiciel** :
- un faux serveur pfrest généré à partir du schéma OpenAPI publié, qui refuse toute requête non conforme ;
- des stubs PHP de pfSense pour exécuter les vrais helpers ;
- un émulateur du helper générique qui applique la même liste blanche ;
- un oracle de diff de `config.xml`.

Les mesures sur équipement sont reportées au déploiement pilote ([`../migration/rollout.md`](../migration/rollout.md)).

## 5. Travaux réalisés

| Lot | Contenu | Verrous |
|---|---|---|
| 0 | inventaire du parc (versions, architectures, DHCP), couverture de l'API par version, état de l'art | V6, V8 |
| 1 | outillage qualité, CI, oracle, scénarios, 9 défauts corrigés, tests de la traduction Kea | V5, V8 |
| 2 | client pfrest : identité, concurrence, dry-run, application ; contrat de l'API | V1, V2, V3, V6 |
| 3 | cycle de vie du paquet, amorçage sans secret humain, moindre privilège | V6, V7 |
| 4 | 14 modules sur l'API, conversions bidirectionnelles | V1, V3, V5 |
| 5 | helper générique sur liste blanche, 9 manques comblés, migration Kea sur l'API | V4, V8 |
| 6 | 33 recettes de déploiement vérifiées hors ligne | — |
| 7 | plan de déploiement progressif et indicateurs | V3, V5, V6 |
| 8 | nettoyage, désinstallation encadrée, synthèse, expérience EXP-01 | V1 |

La chronologie détaillée est dans le [`journal.md`](journal.md), et chaque étape renvoie vers ses commits et ses PR.

## 6. Résultats

Voir [`06-resultats.md`](06-resultats.md). En bref :
- **V1** est levé sur banc logiciel : 0 écriture fausse sur 1 000, contre 52 % sans le mécanisme.
- **V4** est levé par analyse.
- **Les six autres verrous** ont une solution implémentée et testée, et attendent leur mesure de terrain.
- **Défauts de l'existant :** 13, découverts et corrigés.

## 7. Contribution

Voir [`07-contribution.md`](07-contribution.md).

## 8. Suite

Mesures de terrain au pilote, dans l'ordre du plan de déploiement :
- **EXP-02, EXP-03, EXP-05, EXP-06 et EXP-07** : déroulées au pilote ;
- **EXP-08** : captures DHCP et validité de l'option 66 dans Kea.

Chaque résultat sera reporté dans sa fiche et dans [`06-resultats.md`](06-resultats.md).

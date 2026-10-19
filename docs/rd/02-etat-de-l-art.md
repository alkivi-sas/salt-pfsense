# État de l'art

Relevé du 2026-10-19. Il porte sur les moyens de piloter la configuration d'un pfSense depuis un outil de gestion déclarative.

## 1. FauxAPI (solution actuelle)

- Source : https://github.com/ndejong/pfsense_fauxapi. Archivé le 2026-06-07 ; dernière version v1.4 du 2020-05-31, testée jusqu'à pfSense 2.4.5.
- **Modèle.** Accès brut à `config.xml` :
  - `config_get`, `config_set`, `config_patch` ;
  - `function_call` sur une liste de fonctions PHP autorisées ;
  - `send_event` ;
  - sauvegarde et restauration.
- **Limites.**
  - Aucune validation métier.
  - Écriture par section entière.
  - Aucune notion d'identité d'objet.
  - Aucun privilège fin : l'accès donne tout.
  - Plus maintenu.

## 2. pfSense REST API v1 (`pfSense-pkg-API`)

- Source : https://github.com/pfrest/pfSense-pkg-RESTAPI (branche legacy). Dernière v1.9.1 du 2026-08-22. Assets pour CE 2.5 à 2.7 et Plus 22.01 à 24.11.
- **Modèle.** API REST `/api/v1`, modèles validés.
- **Limites.**
  - Ligne en maintenance.
  - API incompatible avec la v2.
  - Seule solution pour les pfSense les plus anciens (2.6, 22.x, 23.01 à 23.09).

## 3. pfSense REST API v2 (`pfSense-pkg-RESTAPI`, « pfrest »)

- Source : https://github.com/pfrest/pfSense-pkg-RESTAPI, documentation https://pfrest.org/. Version v2.10.2 du 2026-08-23.
- **Modèle.**
  - API REST et GraphQL `/api/v2`, avec des modèles typés et validés.
  - Privilèges par endpoint et par méthode HTTP.
  - `dry_run` natif (depuis v2.8.0), endpoints `apply` par domaine.
  - Verrou d'écriture côté serveur ; schéma OpenAPI publié à chaque version.
- **Limites relevées.**
  - **Identifiants.** Un objet est identifié par son index dans `config.xml`, qui n'est pas stable (https://pfrest.org/WORKING_WITH_OBJECT_IDS/).
  - **Opérations au pluriel.** Le PUT remplace toute la liste, et le DELETE n'est pas atomique (https://pfrest.org/ENDPOINT_TYPES/).
  - **Écritures concurrentes.** La documentation déconseille les écritures concurrentes sur `config.xml` (https://pfrest.org/LIMITATIONS_AND_FAQS/).
  - **Couverture.** Pas d'endpoint pour PPPoE, althostnames, sshguard, boot environments, sauvegarde ou restauration de configuration, ni pour certains paquets (sudo, agent de supervision).
  - **Cycle de vie.** Paquet non officiel, supprimé à chaque mise à jour de pfSense. Les endpoints ajoutés localement sont effacés à chaque mise à jour du paquet.
  - **Compatibilité.** Changements cassants fréquents entre versions mineures (2.5, 2.7, 2.9, 2.10). Matrice de compatibilité étroite : une version pfrest par branche pfSense.

## 4. Collection Ansible pfrest

- Source : https://github.com/pfrest/ansible-collection-pfsense.
- **Modèle.**
  - Plus de 400 modules générés à partir du schéma pfrest.
  - Mode check s'appuyant sur `dry_run`.
- **Limites pour notre besoin.**
  - **Hors écosystème.** Écosystème Ansible, alors que l'existant, l'inventaire et l'orchestration sont en SaltStack.
  - **Identité non résolue.** Le problème d'identité stable n'est pas traité : les modules exposent l'`id` positionnel.
  - **Pas de bootstrap.** Aucun bootstrap du paquet ni de la clé API.

## 5. Édition directe de `config.xml` sur l'équipement

- **Modèle.** Script local (PHP CLI) qui utilise `config_get_path`, `config_set_path` et `write_config`.
- **Limites.**
  - Aucune validation.
  - Réimplémentation de l'application des changements domaine par domaine.
  - Dépendance aux fonctions internes de pfSense, qui changent d'une version à l'autre.

## Conclusion

Aucune solution existante ne fournit, pour un moteur déclaratif SaltStack, l'ensemble suivant :
- identité stable des objets ;
- écritures sûres en présence d'autres écrivains ;
- mode test réel ;
- privilèges minimaux ;
- couverture de toutes les fonctions utilisées ;
- installation et amorçage automatiques sur un parc hétérogène.

pfrest v2 est la meilleure base disponible, mais elle doit être complétée sur chacun de ces points. C'est l'objet des verrous décrits dans [`03-verrous.md`](03-verrous.md).

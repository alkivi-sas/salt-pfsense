# Architecture et prérequis

## 1. Objectif

Comprendre comment le master Salt pilote un pare-feu pfSense et ce qui doit être en place avant toute autre recette.

## 2. Prérequis

- Un master Salt 3006 LTS ou 3008 LTS ; le master doit être d'une version supérieure ou égale à celle des minions.
- Sur chaque pare-feu, un minion Salt installé localement (recette 01).
- Une version de pfSense dans le périmètre (FreeBSD 14, 15 ou 16 : CE 2.7+, Plus 23.01+), voir `docs/migration/versions.md`.

## 3. Pillar

Le pillar de chaque pare-feu suit `examples/pillar/pfsense.sls`.

## 4. SLS

Le minion applique les states de ce dépôt (`_states/pfsense_*.py`). Ces states appellent les modules (`_modules/pfsense_*.py`), qui s'adressent localement au pare-feu par l'une de ces trois voies :
- FauxAPI (backend historique, par défaut) ;
- pfSense REST API v2 sur `https://127.0.0.1:<port WebGUI>/api/v2/` ;
- des helpers PHP déployés dans `/opt/helpers`, pour ce que l'API ne couvre pas.

Aucun flux réseau ne sort du pare-feu pour ces appels.

## 5. Commande

`salt '<minion>' test.version`, puis `salt '<minion>' grains.item pfsense_base pfsense_edition pfrest_version`

## 6. Sortie attendue en test=True

Sans objet.

## 7. Vérification

Les grains `pfsense_base` et `pfsense_edition` sont renseignés ; `pfrest_version` est vide tant que la recette 05 n'est pas faite.

## 8. Retour arrière

Sans objet.

## 9. Pièges connus

- **Version de pfrest.** Elle n'est publiée que pour certaines bases de pfSense. Hors de ces bases, la recette 05 échoue explicitement.
- **Paquet non officiel.** pfrest n'est pas un paquet Netgate : il disparaît à chaque mise à jour de pfSense (recette 42).

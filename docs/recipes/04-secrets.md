# Gérer les secrets

## 1. Objectif

Fournir au minion la clé API pfrest et les hashes de mots de passe, sans qu'ils apparaissent en clair dans le dépôt ni dans les sorties.

## 2. Prérequis

Un renderer `gpg` configuré sur le master (ou un ext_pillar Vault, ou `sdb`).

## 3. Pillar

`examples/pillar/pfsense.sls`. La clé `pfsense:restapi:api_key` est chiffrée : générer la valeur avec `openssl rand -hex 32`, puis la chiffrer pour la clé du master.

## 4. SLS

Aucun SLS : la clé est lue par `pfsense_restapi.bootstrapped` directement dans le pillar, jamais passée en argument.

## 5. Commande

`salt '<minion>' pillar.item pfsense:restapi:api_key --out=quiet` : vérifier seulement qu'il n'y a pas d'erreur

## 6. Sortie attendue en test=True

Sans objet.

## 7. Vérification

- `salt-call -l debug state.apply pfsense.restapi` ne fait apparaître ni la clé ni son hash.
- `/usr/local/etc/salt-pfsense/api.key` est en 0600.

## 8. Retour arrière

Générer une nouvelle clé, la publier dans le pillar, puis relancer la recette 05 : l'entrée de clé est remplacée.

## 9. Pièges connus

- **Rotation de la clé.** Changer la clé coupe l'accès API jusqu'au passage suivant de `bootstrapped`.
- **Hashes de mots de passe.** Le pillar porte des hashes bcrypt, pas des mots de passe en clair (recette 13).

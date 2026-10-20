# Clés SSH

## 1. Objectif

Autoriser des clés SSH publiques pour un utilisateur.

## 2. Prérequis

Utilisateur existant (recette 13).

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/users.sls` (state `admin-key`)

## 5. Commande

`salt '<minion>' state.apply pfsense.users test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

`salt '<minion>' pfsense_ssh.auth_keys admin` liste la clé.

## 8. Retour arrière

`pfsense_ssh_auth.absent` avec la même clé.

## 9. Pièges connus

- **Format de la clé.** `name` est la partie encodée de la clé, sans le type ni le commentaire.

# Déployer les helpers PHP

## 1. Objectif

Déployer dans `/opt/helpers` les scripts PHP que les modules appellent localement.

## 2. Prérequis

Recette 02 faite ; le dossier `helpers/` de ce dépôt est exposé comme `salt://pfsense/files/helpers`.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/helpers.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.helpers test=True`, puis sans `test`

## 6. Sortie attendue en test=True

`/opt/helpers` en `result: None` avec la liste des fichiers ajoutés ou modifiés.

## 7. Vérification

`ls -l /opt/helpers` montre `config_path.php`, `restapi_bootstrap.php` et `user_set_fields.php` en 0700, root:wheel.

## 8. Retour arrière

Redéployer la version précédente de `helpers/`.

## 9. Pièges connus

- **`/scripts` n'est plus utilisé.** `pfsense_be` appelle désormais `/opt/helpers/manage_bootenv.php`.
- **Liste blanche figée.** La liste blanche de `config_path.php` est dans le script lui-même : tout nouveau chemin passe par une modification du dépôt.

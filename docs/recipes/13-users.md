# Utilisateurs et groupes

## 1. Objectif

Déclarer les comptes locaux du pare-feu avec leurs privilèges.

## 2. Prérequis

Hashes bcrypt des mots de passe dans le pillar chiffré (recette 04).

## 3. Pillar

```yaml
users:
  ro.admin:
    descr: Read only
    password_hash: <gpg encrypted bcrypt hash>
    priv: [page-dashboard-all]
```

## 4. SLS

`examples/salt/users.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.users test=True`

## 6. Sortie attendue en test=True

Utilisateurs à créer en `result: None` ; un utilisateur dont le hash n'a pas changé n'apparaît pas.

## 7. Vérification

System > User Manager ; le compte FreeBSD existe (`id ro.admin`) ; second passage sans changement.

## 8. Retour arrière

`pfsense_user.absent` ; un compte supprimé ne se restaure qu'à partir d'une sauvegarde de configuration.

## 9. Pièges connus

- **Mot de passe.** Sur pfrest, le hash du pillar est posé par `user_set_fields.php` après la création.
- **Changes Salt.** Les changements renvoyés ne contiennent jamais le hash.

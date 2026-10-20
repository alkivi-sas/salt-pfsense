# Syslog distant

## 1. Objectif

Envoyer les journaux du pare-feu vers un collecteur.

## 2. Prérequis

Collecteur joignable depuis le pare-feu.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/syslog.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.syslog test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

Status > System Logs > Settings ; réception sur le collecteur.

## 8. Retour arrière

Remettre `enable: False`.

## 9. Pièges connus

- **Noms des clés.** Ce sont ceux de `config.xml` (`enable`, `ipproto`, `reverse`) : ils sont traduits pour pfrest.
- **Valeurs numériques.** Les écrire entre guillemets pour rester idempotent.

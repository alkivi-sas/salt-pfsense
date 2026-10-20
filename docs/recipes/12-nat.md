# Redirections de port (NAT)

## 1. Objectif

Déclarer une redirection de port.

## 2. Prérequis

Règle de filtrage correspondante gérée à part (recette 11) : aucune règle associée n'est créée.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/nat_rule.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.nat_rule test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

Firewall > NAT > Port Forward ; second passage sans changement.

## 8. Retour arrière

`pfsense_nat_rule.absent` avec les mêmes paramètres.

## 9. Pièges connus

- **Identité.** Une redirection est identifiée par son protocole, sa cible, son interface, son port local, sa source et sa destination. Changer l'un de ces champs crée une nouvelle redirection : penser à `absent` pour l'ancienne.

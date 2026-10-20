# Réglages sudo et agent zabbix

## 1. Objectif

Régler les paquets sudo et zabbix-agent.

## 2. Prérequis

Paquets installés.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/packages.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.packages test=True`

## 6. Sortie attendue en test=True

Chaque state concerné en `result: None` avec le changement prévu ; aucun state en `False`.

## 7. Vérification

Pages des paquets dans le WebGUI.

## 8. Retour arrière

Remettre la valeur précédente dans le SLS.

## 9. Pièges connus

- **Pas de resynchronisation.** Les paquets ne sont pas resynchronisés automatiquement : redémarrer l'agent zabbix après changement (comme le fait le SLS zabbix existant).

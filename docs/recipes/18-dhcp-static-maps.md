# Static mappings DHCP

## 1. Objectif

Déclarer des réservations DHCP par interface, validées en une seule fois.

## 2. Prérequis

Serveur DHCP actif sur l'interface.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/dhcp_static_map.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.dhcp_static_map test=True`

## 6. Sortie attendue en test=True

Chaque réservation en `result: None` avec le diff `{old, new}` par champ ; `static-maps-applied` annonce l'application.

## 7. Vérification

Services > DHCP Server : réservations présentes ; second passage sans changement.

## 8. Retour arrière

Remettre les anciennes valeurs dans le SLS, ou `absent`, puis repasser.

## 9. Pièges connus

- **State `apply` obligatoire.** Les `present` et `absent` ne font que préparer, rien n'est écrit sans `apply`.
- **Réaffectation d'IP.** Elle est gérée : la suppression passe avant la création.
- **Champs non couverts.** `filename`, `rootpath`, `tftp`, `ldap` et `ddns*` sont refusés sur pfrest.

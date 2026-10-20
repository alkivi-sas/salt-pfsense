# Pairs WireGuard

## 1. Objectif

Ajouter un pair WireGuard à un tunnel existant.

## 2. Prérequis

Paquet WireGuard installé et tunnel créé.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/wireguard.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.wireguard`

## 6. Sortie attendue en test=True

`module.run` est annoncé sans être exécuté.

## 7. Vérification

VPN > WireGuard > Peers : le pair est activé ; `wg show` montre la clé publique.

## 8. Retour arrière

Supprimer le pair dans le WebGUI (pas de fonction de suppression).

## 9. Pièges connus

- **Clé publique.** Elle doit faire 44 caractères.
- **Doublons.** Un pair existant (même nom, clé ou IP) n'est pas modifié.

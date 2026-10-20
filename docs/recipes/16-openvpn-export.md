# Export de configuration OpenVPN

## 1. Objectif

Produire l'archive de configuration OpenVPN d'un utilisateur.

## 2. Prérequis

- Paquet `openvpn-client-export` installé.
- Configuration d'export par défaut définie pour le serveur (VPN > OpenVPN > Client Export).
- Certificat de l'utilisateur créé (recette 15).

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

`examples/salt/openvpn_export.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.openvpn_export`

## 6. Sortie attendue en test=True

`module.run` est annoncé sans être exécuté.

## 7. Vérification

La sortie renvoie le chemin du fichier produit dans `/tmp`.

## 8. Retour arrière

Supprimer le fichier produit.

## 9. Pièges connus

- **`conf_type`.** Il reprend les types du paquet (`confzip`, `confinline`, `visc`, `inst-*`).
- **Plusieurs serveurs.** S'il y a plusieurs serveurs, préciser `vpnid`.

# Certificats utilisateur et révocation

## 1. Objectif

Créer le certificat VPN d'un utilisateur et révoquer celui d'un autre.

## 2. Prérequis

Une CA et une CRL interne existent sur le pare-feu ; utilisateur existant.

## 3. Pillar

`pfsense:pki:dn` dans `examples/pillar/pfsense.sls` (sujet des certificats générés).

## 4. SLS

`examples/salt/user_cert.sls`

## 5. Commande

`salt '<minion>' state.apply pfsense.user_cert test=True`

## 6. Sortie attendue en test=True

`alice-certificate` en `result: None` s'il n'a pas encore de certificat de la CA ; `module.run` est annoncé sans être exécuté.

## 7. Vérification

System > Certificates : certificat `alice` de type user ; `pfsense_certificate.get_crl_revoked_list <crl>` contient celui de bob.

## 8. Retour arrière

Annuler une révocation : supprimer l'entrée dans System > Certificates > Revocation (pas de state dédié).

## 9. Pièges connus

- **Plusieurs CA.** S'il y en a plusieurs, préciser `caref` ; s'il y a plusieurs CRL, préciser `crlid`.
- **Clé privée.** Elle n'est jamais renvoyée par le module.

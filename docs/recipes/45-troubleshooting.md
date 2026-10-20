# Dépannage

## 1. Objectif

Diagnostiquer un échec sur le backend pfrest.

## 2. Prérequis

Aucun prérequis spécifique.

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

Aucun SLS.

## 5. Commande

`salt-call -l debug state.apply <sls>` sur le pare-feu

## 6. Sortie attendue en test=True

Sans objet.

## 7. Vérification

Lire le `response_id` de l'erreur `pfrest <code> <response_id>` :
- `FIELD_UNKNOWN` ou `FIELD_READ_ONLY` : version de pfrest différente du contrat ;
- `403` : privilège manquant dans `pfrest_lifecycle.ENDPOINTS` ;
- `SALT_PFSENSE_CONFLICT` : écriture tierce pendant le run, relancer ;
- `SALT_PFSENSE_AMBIGUOUS_KEY` : doublon de clé métier à nettoyer à la main.

## 8. Retour arrière

Recette 44.

## 9. Pièges connus

- **Coupure de l'API.** L'API est indisponible quelques secondes après un redémarrage du WebGUI (recette 23).
- **Journaux.** Les journaux de pfrest se trouvent dans Status > System Logs > Packages.

# EXP-01 — Stabilité des identifiants sous suppressions et insertions

- **Verrou :** V1
- **Dates :** 2026-10-20
- **Commits / PR :** `tests/unit/test_exp01_identity.py` (lot 8) ; mécanisme dans `_utils/pfrest.py` (`find_one`, `write_checked`, lot 2)

## Hypothèse

Résoudre l'identifiant juste avant chaque écriture par la clé métier, puis revérifier l'objet après écriture, suffit à ne jamais écrire sur un mauvais objet, même lorsque les positions changent entre deux opérations.

## Protocole

Banc : le faux serveur `tests/fake_pfrest.py`, qui reproduit la règle de pfrest (identifiant = position dans la liste). Graine aléatoire fixe (20261020).

- **Essai A :** 1 000 opérations aléatoires (création, mise à jour, suppression) par `write_checked` sur des alias. Elles sont entrecoupées d'écritures d'un tiers, insertion et suppression à une position aléatoire, qui décalent les identifiants. Après chaque opération, l'état complet est comparé à l'état attendu.
- **Essai B (contre-exemple) :** 200 mises à jour avec un identifiant résolu **avant** une réorganisation par un tiers, puis réutilisé.

## Résultats bruts

| Essai | Opérations | Écritures sur un mauvais objet |
|---|---|---|
| A : clé métier, résolution juste avant l'écriture | 1 000 | **0** |
| B : identifiant mis en cache | 200 | **105** (52,5 %) |

## Analyse

L'essai B montre que le risque est réel et massif dès que les positions bougent : réutiliser un identifiant positionnel est faux une fois sur deux dans ce scénario. L'essai A montre que la résolution par clé métier élimine ce risque **entre deux opérations**.

Il reste une fenêtre entre la résolution et l'écriture elle-même. Un tiers qui écrit dans cet intervalle est détecté par la vérification de révision de `config_lock` (V2, test `test_conflict_detected_inside_lock`), qui fait échouer le run au lieu d'écrire à côté.

## Conclusion

Hypothèse confirmée sur le banc logiciel ; critère de levée de V1 atteint sur ce banc (0 sur 1 000). La confirmation sur un pfrest réel reste à faire au déploiement pilote.

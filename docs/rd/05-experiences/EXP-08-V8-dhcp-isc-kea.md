# EXP-08 — Équivalence des offres DHCP ISC / Kea

- **Verrou :** V8
- **Dates :** début 2026-10-20 (préparation), fin —
- **Commits / PR :** tests unitaires `test(dhcp_kea)` (lot 1) ; protocole dans `docs/migration/lab.md` §4

## Hypothèse

Une table de traduction fermée (pillar `pfsense:dhcp_kea:options`), qui refuse explicitement toute option inconnue ou tout failover, produit après migration une offre DHCP identique, vue du client, à celle du serveur ISC.

## Protocole

Lab : CE 2.8.1, CE 2.9.0 et Plus 26.07, chacun avec un client Linux sur chaque interface DHCP. Snapshot `isc-options` :
- `lan` : options 43 et 132 ;
- `opt1` : options 132 et 66 ;
- un static mapping.

Pour chaque interface :
1. capture du DHCPACK en ISC ;
2. migration par le state `pfsense_dhcp_kea.migrated` ;
3. capture du DHCPACK en Kea ;
4. comparaison option par option.

Puis second passage (idempotence) et cas de refus (failover, option hors table). Détail : `docs/migration/lab.md` §4.

## Résultats bruts

Étape préalable sans lab (2026-10-20) : 9 tests unitaires verts sur la traduction.
- Option binaire en hexadécimal, option chaîne avec `always-send`.
- Pare-feu sans DHCP.
- Idempotence.
- Refus : failover, option hors table, valeur non hexadécimale, JSON Kea divergent (interface et global).

Captures lab : à faire.

## Analyse

**Incertitude identifiée avant le lab.** Kea interdit probablement de redéfinir une option standard de l'espace `dhcp4` par une `option-def`, l'option 43 faisant exception. Or la traduction actuelle produit une `option-def` pour chaque option de la table. L'option 66, présente sur 3 pare-feux du périmètre, pourrait donc exiger un traitement différent : `option-data` sous son nom standard, sans `option-def`. À confirmer ou infirmer sur `opt1`.

## Conclusion

À compléter.

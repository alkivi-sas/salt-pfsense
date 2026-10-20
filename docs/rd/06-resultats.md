# Résultats

État au 2026-10-20, avant déploiement. « Banc logiciel » désigne les tests automatisés : faux serveur pfrest validé par le contrat de l'API, stubs PHP de pfSense, émulateur du helper. Aucun pare-feu de test n'était disponible : les mesures de terrain sont à faire au pilote ([`../migration/rollout.md`](../migration/rollout.md)).

| Verrou | Solution | Résultat sur banc logiciel | Reste à mesurer | Fiches |
|---|---|---|---|---|
| V1 identifiants volatils | résolution par clé métier juste avant l'écriture, revérification après (`find_one`, `write_checked`) | 0 écriture fausse sur 1 000 opérations aléatoires ; 105 sur 200 sans le mécanisme | confirmation sur pfrest réel | EXP-01 |
| V2 concurrence | verrou de run sur le minion et comparaison de la révision de configuration avant chaque écriture | écriture tierce détectée, run en échec, aucune écriture faite | runs parallèles et WebGUI sur un vrai pare-feu | EXP-02 |
| V3 écriture / application | application immédiate par défaut ou différée par domaine (`pfsense_apply`) | 1 seul apply par domaine et par run en mode différé ; aucun apply sans écriture | nombre de rechargements pf et durée de run, avant et après | EXP-03 |
| V4 couverture | helper générique sur liste blanche (8 chemins, 4 actions) plutôt qu'endpoints ajoutés | 9 manques couverts ; refus explicite du reste ; helpers testés contre stubs | survie sur cycles de mise à jour réels | EXP-04 |
| V5 équivalence | conversions bidirectionnelles, lectures sur `config.xml`, oracle de diff normalisé | formes de retour identiques à FauxAPI dans les tests ; 4 défauts d'idempotence trouvés et corrigés | registre d'écarts `config.xml` par module sur pare-feu réel | EXP-05 |
| V6 versions | une version épinglée (v2.10.2) pour 152 pare-feux, contrat extrait de l'OpenAPI, requêtes validées contre lui | chaque endpoint et méthode utilisés existent dans le contrat ; toute requête testée est conforme | arm64 (102 pare-feux), armv7 (6) | EXP-06 |
| V7 amorçage | clé générée hors du pare-feu, hash écrit localement avec utilisateur et groupe dédiés | amorçage idempotent sur stubs ; clé jamais dans la requête au helper ni dans les sorties | authentification et privilèges sur pfrest réel | EXP-07 |
| V8 ISC → Kea | table de traduction fermée en pillar, backend basculé en dernier | 11 tests (traduction, refus, ordre des écritures, idempotence) | offres DHCP comparées par capture ; validité de l'option 66 dans Kea | EXP-08 |

## Défauts trouvés et corrigés pendant les travaux

Treize défauts de l'existant, chacun avec un test qui échoue avant la correction :
- chemin d'un helper ;
- journalisation ;
- deux messages ;
- création du premier VLAN ;
- quatre modes test ;
- quatre défauts d'idempotence (syslog, mot de passe, VLAN, interface) ;
- export OpenVPN du premier certificat ;
- création de certificat sous Python 3.

## Indicateurs du code

- 192 tests automatisés.
- 14 modules sur l'API, 9 manques sur le helper générique.
- 33 recettes de déploiement vérifiées hors ligne.

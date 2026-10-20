# EXP-04 — Endpoint pfrest ajouté contre helper générique

- **Verrou :** V4
- **Dates :** 2026-10-20, analyse du code source ; aucun banc disponible
- **Commits / PR :** `feat(helpers): generic allowlisted config path helper` et suivants (lot 5)

## Hypothèse

Pour les données que pfrest ne modélise pas, un helper local générique sur liste blanche est plus durable qu'un endpoint ajouté à pfrest. La raison supposée : les ajouts locaux seraient effacés à chaque mise à jour du paquet.

## Protocole

Prévu : prototype d'un endpoint `SystemWebGUIAltHostnames` dans `/usr/local/pkg/RESTAPI/`, régénération (`pfsense-restapi buildendpoints`), puis trois cycles `pfsense-restapi update` en vérifiant la survie de l'endpoint.

Réalisé, faute de banc : lecture du paquet v2.10.2 (`pfSense-2.8.1-pkg-RESTAPI.pkg`), en particulier :
- les scripts d'installation et de désinstallation ;
- la commande de mise à jour (`manage.php`).

## Résultats bruts

- **Mise à jour du paquet.** `pfsense-restapi update` et `revert` exécutent `pkg-static delete -y`, puis `pkg-static add`.
- **Désinstallation.** Le script supprime les endpoints, formulaires, caches et schémas générés (`/usr/local/www/api/v2/*`).
- **Sauvegarde.** Les classes de `/usr/local/pkg/RESTAPI/` appartiennent au paquet et sont remplacées à chaque installation. Seule la configuration du paquet est sauvegardée et restaurée (`backup.json`), jamais du code.
- **Mise à jour de pfSense.** Le paquet est retiré, puis réinstallé par le state `pfsense_restapi.installed`.

## Analyse

Un endpoint ajouté devrait être redéposé, et les endpoints régénérés, après chaque installation ou mise à jour du paquet ou de pfSense. Cela crée un couplage fort avec les classes internes de pfrest (`Model`, `Endpoint`, champs), qui changent entre versions mineures (voir `docs/migration/coverage.md`).

Le helper générique ne dépend que de fonctions stables de pfSense : `config_get_path`, `config_set_path`, `config_del_path` et `write_config`. Il ne s'efface pas, puisqu'il est déployé par Salt dans `/opt/helpers`. Sa surface est bornée par une liste blanche de 8 motifs de chemins et de 4 actions d'application. Il est testé contre des stubs PHP.

## Conclusion

Hypothèse retenue par analyse, sans mesure. Décision : un helper générique (`helpers/config_path.php`) pour tous les manques fonctionnels ; aucun endpoint ajouté à pfrest. La mesure de survie sur trois cycles reste à faire si un banc devient disponible.

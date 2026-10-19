# Démarche expérimentale

## Principe

Chaque verrou est traité par une ou plusieurs expériences. Une expérience comprend :
- une hypothèse ;
- un protocole reproductible ;
- des mesures brutes conservées ;
- une analyse et une conclusion, même négative.

Les expériences tournent sur un banc dédié, jamais sur le parc de production.

## Banc d'essai

- **Équipements.** Machines virtuelles pfSense aux versions de la matrice de compatibilité (voir `../migration/versions.md`). Chacune porte un agent SaltStack et les deux couches d'accès côte à côte, l'ancienne et la nouvelle.
- **Snapshots.** Des instantanés nommés (`clean`, `fauxapi`, `pfrest`) permettent de rejouer chaque scénario à partir d'un état connu.
- **Oracle `config.xml`.** Il compare le `config.xml` produit par chaque implémentation pour un même état désiré. Il normalise d'abord l'ordre des clés, les booléens et les encodages, et exclut les champs horodatés. Chaque écart restant doit être expliqué dans un registre.
- **Scénarios standard, par state :**
  1. création ;
  2. second passage (idempotence) ;
  3. modification ;
  4. mode test ;
  5. suppression ;
  6. second passage de la suppression.
- **Mesures.** Durée de run, nombre de lectures complètes de configuration, nombre de rechargements pf, captures réseau (DHCP).

## Reproductibilité

- **Code.** Les scripts du banc, les scénarios et l'oracle sont versionnés dans le dépôt (`tests/`).
- **Traçabilité des résultats.** Chaque résultat cité dans une fiche d'expérience renvoie au commit et à la PR qui l'ont produit.
- **Preuves.** Elles sont stockées anonymisées dans `preuves/`.

## Outils

SaltStack, pfSense CE et Plus, pfSense REST API v2 (versions épinglées), pytest, tcpdump, et les schémas OpenAPI publiés par pfrest.

# salt-pfsense

Extensions SaltStack (modules d'exécution, states, utils, grains) et helpers PHP pour gérer de façon déclarative la configuration de pare-feux pfSense. Le minion Salt tourne sur le pare-feu et agit localement.

## Backends

Chaque module choisit son backend au moment de l'appel. Le choix se fait dans le pillar :

```yaml
pfsense:
  api_backend: pfrest          # fauxapi par défaut
  api_backend_overrides:
    pfsense_alias: fauxapi     # surcharge par module
```

- **`fauxapi`** : backend historique (FauxAPI, archivé), conservé pour les pare-feux hors périmètre.
- **`pfrest`** : pfSense REST API v2, version épinglée dans `_utils/pfrest_lifecycle.py`. Il couvre les versions de pfSense sur FreeBSD 14, 15 ou 16. Ce que l'API ne modélise pas passe par `helpers/config_path.php`, limité par une liste blanche.

## Contenu

| Dossier | Rôle |
|---|---|
| `_modules/`, `_states/` | fonctions et states `pfsense_*` ; interface publique stable quel que soit le backend |
| `_utils/` | clients FauxAPI (`pfsense.py`) et pfrest (`pfrest.py`), implémentations pfrest par domaine (`pfrest_*.py`) |
| `_grains/` | version et édition de pfSense, version de pfrest installée |
| `helpers/` | scripts PHP déployés dans `/opt/helpers` |
| `pfrest/` | contrat de l'API extrait du schéma OpenAPI publié |
| `examples/` | pillar et SLS d'exemple des recettes |
| `docs/recipes/` | recettes de déploiement et d'exploitation |
| `docs/migration/` | plan de migration, inventaires, couverture, plan de déploiement |
| `docs/rd/` | documentation R&D : verrous, expériences, journal |
| `tests/` | tests unitaires, faux serveur pfrest validé par le contrat, tests des helpers PHP, scénarios de lab |

## Déployer

Suivre les recettes dans l'ordre : [`docs/recipes/README.md`](docs/recipes/README.md). Les recettes 00 à 07 forment le socle, puis viennent une recette par domaine et les recettes d'exploitation.

## Développer

```bash
pipenv install --dev
pipenv run pre-commit run --all-files
pipenv run pytest            # tests unitaires ; -m lab pour les scénarios sur un pare-feu de test
```

Le code historique est exclu du formatage automatique tant qu'il n'est pas réécrit (`.pre-commit-config.yaml`). Le nouveau code est typé et vérifié par black, flake8 et mypy.

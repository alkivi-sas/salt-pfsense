# Journal de déploiement

Une entrée par étape de [`rollout.md`](rollout.md). Les pare-feux sont désignés par leur identifiant anonyme.

## Modèle d'entrée

```
## AAAA-MM-JJ — <pilote | vague N | cas particulier>

- Pare-feux : FW-…
- Modules basculés : …
- test=True : <aucun changement | écarts : …>
- Second passage : <n>/<total> à zéro changement
- Écarts config.xml : <aucun | expliqués : … (accepted_diffs.yaml)>
- Durée highstate : avant … s, après … s
- Rechargements pf par run : avant …, après …
- Incidents / retours arrière : …
- Décision : <passage à l'étape suivante | arrêt, motif>
```

## Entrées

Aucune pour l'instant : le déploiement n'a pas commencé.

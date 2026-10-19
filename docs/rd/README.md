# Documentation R&D

Ce dossier regroupe ce qui sert à justifier les travaux de R&D du projet : verrous, démarche, expériences et résultats. Il est rempli au fil des lots décrits dans [`../migration/plan.md`](../migration/plan.md). Le document final est assemblé à partir de ce contenu au lot 8 ; on ne le réécrit pas après coup.

| Fichier | Contenu |
|---|---|
| [`01-contexte.md`](01-contexte.md) | problème, enjeux, périmètre, objectifs mesurables |
| [`02-etat-de-l-art.md`](02-etat-de-l-art.md) | solutions existantes, et pourquoi elles ne suffisent pas |
| [`03-verrous.md`](03-verrous.md) | verrous V1 à V8 : hypothèse, protocole, critère de levée, statut |
| [`04-demarche.md`](04-demarche.md) | méthode expérimentale et outillage |
| [`05-experiences/`](05-experiences/) | une fiche par expérience (`EXP-NN-<verrou>-<sujet>.md`) |
| [`06-resultats.md`](06-resultats.md) | résultats par verrou, indicateurs avant/après |
| [`07-contribution.md`](07-contribution.md) | ce qui est nouveau par rapport à l'état de l'art |
| [`journal.md`](journal.md) | journal de bord daté |
| [`temps.csv`](temps.csv) | temps passé par tâche, en distinguant R&D et développement |
| [`preuves/`](preuves/) | captures, mesures, extraits d'oracle (anonymisés) |

## Conventions

- **Anonymisation.**
  - Aucun nom de client, d'équipement nominatif, de domaine interne ni d'adresse IP publique.
  - Les pare-feux sont désignés par un identifiant `FW-NNN`.
  - La correspondance entre identifiant et équipement est tenue hors dépôt (`docs/rd/private/`, ignoré par Git).
- **Références.** Chaque PR cite les verrous concernés (`Refs: V1, V5`) et, le cas échéant, la fiche d'expérience (`EXP-NN`).
- **Échecs.** Une expérience qui échoue a sa fiche, comme une expérience qui réussit.
- **Temps.** Chaque ligne de `temps.csv` porte la catégorie `rd` (verrou, expérimentation, prototype) ou `dev` (développement courant, documentation d'exploitation, déploiement).

# Contribution

Ce que les travaux apportent par rapport à l'état de l'art ([`02-etat-de-l-art.md`](02-etat-de-l-art.md)) :

1. **Identité stable** au-dessus d'une API à identifiants positionnels (V1).
   - Une clé métier par type d'objet, et un cycle « résoudre, écrire, revérifier ».
   - Efficacité mesurée : 0 erreur contre 52 % sans le mécanisme.
   - La collection Ansible de référence expose l'identifiant positionnel tel quel.
2. **Écritures sûres** sur une configuration non transactionnelle partagée avec d'autres écrivains (V2). Sérialisation locale et détection d'écriture tierce par l'historique de configuration.
3. **Double backend aiguillé par module et par équipement**, avec contrat public inchangé. Il permet une migration progressive et réversible d'un parc hétérogène : FreeBSD 11 à 16, trois architectures.
4. **Banc de test sans équipement** :
   - un faux serveur dérivé automatiquement du schéma OpenAPI publié, qui refuse toute requête non conforme ;
   - des stubs PHP pour exécuter les vrais helpers pfSense ;
   - un oracle de diff normalisé de `config.xml`.
5. **Amorçage d'une clé API sans secret humain** (V7) : la clé est générée par l'outil de gestion, seul son hash est écrit, avec des privilèges dérivés des endpoints réellement utilisés.
6. **Comblement contrôlé des manques d'une API** par un helper générique sur liste blanche, plutôt que par extension de l'API (V4), choix argumenté par l'analyse du cycle de vie du paquet.
7. **Traduction fermée des options DHCP ISC vers Kea** (V8), avec refus explicite de tout cas non couvert et ordre d'écriture garantissant que le nouveau serveur ne démarre jamais sans ses options.

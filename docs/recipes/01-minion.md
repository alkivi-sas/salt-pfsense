# Installer le minion Salt sur pfSense

## 1. Objectif

Installer et démarrer un minion Salt sur le pare-feu, rattaché au master.

## 2. Prérequis

Accès console ou SSH administrateur au pare-feu ; nom du minion défini (convention `gateway.<site>`).

## 3. Pillar

Aucun pillar spécifique.

## 4. SLS

Installation hors SLS, une seule fois :
1. Installer le paquet `py3xx-salt` dont l'ABI correspond à la base FreeBSD du pare-feu (`pkg add` d'une URL de `pkg.freebsd.org`), sans activer le dépôt FreeBSD dans pfSense.
2. `sysrc salt_minion_enable=YES` ;
3. Écrire `/usr/local/etc/salt/minion` (`master:`, `id:`).
4. `service salt_minion start`.

## 5. Commande

Sur le master : `salt-key -a <minion>`, puis `salt '<minion>' test.ping`

## 6. Sortie attendue en test=True

Sans objet.

## 7. Vérification

`test.ping` renvoie `True` et `salt '<minion>' grains.item osfinger` renvoie la version de FreeBSD.

## 8. Retour arrière

`service salt_minion stop`, `pkg delete py3xx-salt`, `salt-key -d <minion>`.

## 9. Pièges connus

- **ABI.** Une version de FreeBSD différente de la base pfSense casse les bibliothèques partagées : vérifier `pkg -vv | grep ABI` avant.
- **Clés du minion.** Sauvegarder `/usr/local/etc/salt/pki/minion`. Une réinstallation de pfSense les perd, et il faudra alors réaccepter la clé.

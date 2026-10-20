# Lab pfSense (T1.3, T1.4, T1.6, T1.8)

Banc réduit à pfSense Plus 26.07 (amd64 et armv7) : checklist dans [`banc-2607.md`](banc-2607.md).

Le lab sert à :
- rejouer les scénarios de référence sur les deux backends ;
- enregistrer des fixtures réelles ;
- mesurer les verrous (`docs/rd/03-verrous.md`).

Il n'est jamais connecté au parc de production.

## 1. Composition (T1.3)

Bases et architectures du périmètre (voir [`versions.md`](versions.md)) :

| Nom | Édition | Version | Arch. | Support |
|---|---|---|---|---|
| `lab-ce281` | CE | 2.8.1 | amd64 | VM |
| `lab-ce290` | CE | 2.9.0 | amd64 | VM |
| `lab-plus2607` | Plus | 26.07 | amd64 | VM (licence Plus) |
| `lab-plus2607-arm64` | Plus | 26.07 | arm64 | boîtier Netgate |
| `lab-plus2607-armv7` | Plus | 26.07 | armv7 | boîtier Netgate (pour V6, armv7 non supporté officiellement par pfrest) |
| `lab-client` | Linux | — | amd64 | VM cliente sur le LAN de chaque pare-feu (captures DHCP) |

Chaque pare-feu a :
- deux interfaces au minimum, WAN (`wan`) et LAN (`lan`, DHCP actif) ;
- une troisième interface en option, `opt1`, avec DHCP, pour les scénarios multi-interfaces ;
- un minion Salt rattaché au master du lab ;
- FauxAPI installé comme sur le parc (SLS `pfsense/api`) ;
- pfrest v2.10.2, à installer au lot 3 ;
- les helpers dans `/opt/helpers`.

Snapshots à prendre sur chaque VM :

| Snapshot | État |
|---|---|
| `clean` | installation fraîche, minion accepté, FauxAPI et helpers déployés |
| `isc-options` | `clean` + DHCP ISC avec les options de la section 4 |
| `pfrest` | `clean` + pfrest installé et amorcé (lot 3) |

Pour les boîtiers physiques, la sauvegarde et la restauration de `config.xml` (Diagnostics > Backup & Restore) remplacent les snapshots.

## 2. Fixtures (T1.4)

À enregistrer dans `tests/fixtures/<backend>/<nom>.json` à partir du snapshot `clean` :
- **FauxAPI :** `salt <minion> pfsense_config.get <section>` pour `aliases`, `filter`, `nat`, `system:user`, `cron`, `vlans`, `dhcpd`, `cert`, `ca`, `crl`, `installedpackages:wireguard`.
- **pfrest :** au lot 3, une réponse GET par endpoint de [`coverage.md`](coverage.md).

**Avant commit :** vérifier qu'aucune valeur `**REDACTED**`, aucune clé ni aucun mot de passe n'y figure. Le lab n'utilise que des adresses de documentation : 192.0.2.0/24, 198.51.100.0/24 et le réseau LAN par défaut.

## 3. Scénarios de référence (T1.6)

Les scénarios sont dans `tests/lab/scenarios/<state>/`, chacun avec `create.sls`, `absent.sls` et éventuellement `modify.sls`. Le runner `tests/lab/test_scenarios.py` enchaîne, pour chaque scénario :

1. `create` : au moins un changement, aucun échec ;
2. `create` à nouveau : aucun changement (idempotence) ;
3. `modify`, s'il existe : au moins un changement ;
4. `absent` en `test=True` : aucun échec, au moins un state à `result: None` ;
5. `absent` : au moins un changement ;
6. `absent` à nouveau : aucun changement.

Les défauts connus du backend FauxAPI sont marqués `xfail` dans `KNOWN_ISSUES`, avec leur raison. Ils forment la ligne de base qui sera comparée au backend pfrest au lot 4.

### Lancer

1. Rendre les scénarios accessibles au master sous `lab.<scenario>.<step>` : copie ou lien de `tests/lab/scenarios/` vers `<file_roots>/lab/`.
2. Synchroniser les extensions : `salt <minion> saltutil.sync_all`.
3. Optionnel : définir le parent des VLAN dans le pillar du lab (`lab:vlan_parent`, par défaut `vtnet1`).
4. Depuis une machine qui atteint le master :

```bash
export LAB_MINION=lab-ce281
export LAB_SALT="ssh lab-master sudo salt"   # ou "salt" sur le master lui-même
pipenv run pytest -m lab tests/lab -v
```

5. Restaurer le snapshot `clean` avant de rejouer sur un autre backend.

### Oracle `config.xml` (EXP-05, lot 4)

Pour un même scénario joué sur chaque backend depuis le même snapshot :

```bash
scp lab-ce281:/cf/conf/config.xml fauxapi.xml   # après create sur le backend FauxAPI
scp lab-ce281:/cf/conf/config.xml pfrest.xml    # après create sur le backend pfrest
pipenv run python tests/oracle/diff_config.py fauxapi.xml pfrest.xml
```

Chaque écart restant est expliqué, puis ajouté à `tests/oracle/accepted_diffs.yaml`.

## 4. Migration Kea et captures DHCP (T1.8, EXP-08)

**Préparation du snapshot `isc-options`, en ISC :**
- `lan` : option 43 (chaîne `01:04:C0:00:02:0A`) et option 132 (texte `200`) ;
- `opt1` : options 132 (`200`) et 66 (texte `192.0.2.30`) ;
- un static mapping sur `lan` pour la MAC de `lab-client`.

Pillar du lab : la table de [`dhcp.md`](dhcp.md), plus l'option 66 à valider :

```yaml
pfsense:
  dhcp_kea:
    options:
      '43': {name: unificontroller, type: binary, format: hex}
      '132': {name: yealink-vlan, type: string, always-send: true}
      '66': {name: tftp-server-name, type: string, always-send: true}
```

**Point à vérifier en priorité (non vérifié).**
- **Contrainte supposée.** Kea refuse sans doute une `option-def` qui redéfinit une option standard de l'espace `dhcp4`, sauf l'option 43 qui est redéfinissable. L'option 66 (`tftp-server-name`) est standard.
- **Conséquence possible.** `pfsense_dhcp_kea._option_def()` crée une `option-def` pour chaque entrée du pillar ; il produirait alors une configuration que Kea rejette.
- **À tester sur `opt1`.** Si Kea refuse de démarrer, il faudra une clé pillar (par exemple `standard: true`) qui n'émet que l'`option-data`, sous le nom standard, sans `option-def`. Ce serait une évolution du module, à décider après le test.

**Procédure, pour `lan` puis pour `opt1` :**

1. Sur `lab-client`, capture de l'échange DHCP complet en ISC :

```bash
sudo tcpdump -i eth0 -n -vvv -w isc-<if>.pcap 'port 67 or port 68' &
sudo dhclient -r eth0 && sudo dhclient -v eth0
sudo kill %1
```

2. Migration : `salt <minion> state.apply pfsense.dhcp.kea test=True`, puis sans `test`.
3. Vérifier que le serveur DHCP actif est Kea : `pgrep -l kea-dhcp4` répond et `pgrep -l dhcpd` ne répond plus.
4. Même capture qu'à l'étape 1, nommée `kea-<if>.pcap`.
5. Comparer les options du DHCPACK :

```bash
for f in isc-<if>.pcap kea-<if>.pcap; do
  tshark -r "$f" -Y 'dhcp.option.dhcp == 5' -V | grep -E '^\s+Option: \(' > "$f.options"
done
diff isc-<if>.pcap.options kea-<if>.pcap.options
```

6. Critère (V8) : mêmes options, mêmes valeurs, même durée de bail. Les captures et la sortie du `diff` vont dans `docs/rd/preuves/EXP-08/`, sans adresse MAC réelle.
7. Second passage de `state.apply pfsense.dhcp.kea` : aucun changement.
8. Cas de refus à vérifier (le state doit échouer sans rien modifier) :
   - failover configuré sur `lan` ;
   - option 66 retirée de la table du pillar.

Les résultats sont consignés dans la fiche `docs/rd/05-experiences/EXP-08-V8-dhcp-isc-kea.md`.

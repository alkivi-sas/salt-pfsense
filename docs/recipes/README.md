# Recettes de déploiement Salt

Chaque recette suit le même format en neuf sections. Les fichiers cités dans `examples/` sont les vrais fichiers utilisés ; `tests/test_recipes.py` vérifie la structure des recettes, l'existence des fichiers cités, le rendu des SLS d'exemple et l'existence des fonctions qu'ils appellent.

| Recette | Sujet |
|---|---|
| [00-architecture.md](00-architecture.md) | Architecture et prérequis |
| [01-minion.md](01-minion.md) | Installer le minion Salt sur pfSense |
| [02-extensions.md](02-extensions.md) | Distribuer les extensions |
| [03-helpers.md](03-helpers.md) | Déployer les helpers PHP |
| [04-secrets.md](04-secrets.md) | Gérer les secrets |
| [05-restapi.md](05-restapi.md) | Installer et amorcer pfrest |
| [06-backend.md](06-backend.md) | Basculer un pare-feu de FauxAPI vers pfrest |
| [07-apply.md](07-apply.md) | Ordonnancer les applies |
| [10-alias.md](10-alias.md) | Alias |
| [11-filter-rules.md](11-filter-rules.md) | Règles de filtrage |
| [12-nat.md](12-nat.md) | Redirections de port (NAT) |
| [13-users.md](13-users.md) | Utilisateurs et groupes |
| [14-ssh-keys.md](14-ssh-keys.md) | Clés SSH |
| [15-pki.md](15-pki.md) | Certificats utilisateur et révocation |
| [16-openvpn-export.md](16-openvpn-export.md) | Export de configuration OpenVPN |
| [17-wireguard.md](17-wireguard.md) | Pairs WireGuard |
| [18-dhcp-static-maps.md](18-dhcp-static-maps.md) | Static mappings DHCP |
| [18b-dhcp-kea.md](18b-dhcp-kea.md) | Migrer le DHCP d'ISC vers Kea |
| [19-vlan-interfaces.md](19-vlan-interfaces.md) | VLAN et interfaces |
| [20-dns.md](20-dns.md) | Serveurs DNS système |
| [21-syslog.md](21-syslog.md) | Syslog distant |
| [22-cron.md](22-cron.md) | Tâches cron |
| [23-webgui.md](23-webgui.md) | WebGUI et noms d'hôte alternatifs |
| [24-sshguard.md](24-sshguard.md) | Liste blanche sshguard |
| [25-packages.md](25-packages.md) | Réglages sudo et agent zabbix |
| [26-pppoe.md](26-pppoe.md) | PPPoE noyau |
| [27-boot-environments.md](27-boot-environments.md) | Boot environments |
| [40-rollout.md](40-rollout.md) | Déploiement sur le parc |
| [41-ha.md](41-ha.md) | Haute disponibilité (CARP) |
| [42-post-upgrade.md](42-post-upgrade.md) | Après une mise à jour de pfSense |
| [43-pfrest-upgrade.md](43-pfrest-upgrade.md) | Monter la version de pfrest |
| [44-rollback.md](44-rollback.md) | Retour arrière |
| [45-troubleshooting.md](45-troubleshooting.md) | Dépannage |
| [46-fauxapi-removal.md](46-fauxapi-removal.md) | Désinstaller FauxAPI |

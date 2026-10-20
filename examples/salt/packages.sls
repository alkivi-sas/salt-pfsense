# sudo and zabbix agent package settings (recipe 25)
zabbix-server:
  pfsense_zabbix_configuration.present:
    - name: server
    - value: 198.51.100.7

sudo-enabled:
  pfsense_sudo_configuration.present:
    - name: enable
    - value: 'on'

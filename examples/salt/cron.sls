# Cron job (recipe 22)
backup-config:
  pfsense_cron.present:
    - name: /usr/local/bin/backup-config.sh
    - identifier: backup-config
    - minute: 0
    - hour: 3

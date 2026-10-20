# sshguard whitelist (recipe 24)
admin-network:
  pfsense_sshguard_whitelist.present:
    - name: 192.0.2.0/24

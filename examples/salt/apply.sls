# Deferred apply: one firewall apply after every change of the run (recipe 07)
admin-alias:
  pfsense_alias.present:
    - name: ADMIN
    - type: host
    - target:
      - 192.0.2.10
      - 192.0.2.11

admin-https:
  pfsense_filter_rule.present:
    - name: admin https
    - interface: wan
    - type: pass
    - protocol: tcp
    - source:
        address: ADMIN
    - destination:
        network: wanip
        port: '443'

firewall-applied:
  pfsense_apply.applied:
    - name: firewall
    - onchanges:
      - pfsense_alias: admin-alias
      - pfsense_filter_rule: admin-https

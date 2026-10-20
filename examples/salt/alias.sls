# Host, network and port aliases (recipe 10)
admin-alias:
  pfsense_alias.present:
    - name: ADMIN
    - type: host
    - descr: administration hosts
    - target:
      - 192.0.2.10
      - 192.0.2.11

web-ports:
  pfsense_alias.present:
    - name: WEB_PORTS
    - type: port
    - target:
      - '80'
      - '443'

old-alias:
  pfsense_alias.absent:
    - name: OLD_ALIAS

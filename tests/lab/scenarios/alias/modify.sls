lab-alias:
  pfsense_alias.present:
    - name: LAB_ALIAS
    - type: host
    - target:
      - 192.0.2.10
      - 192.0.2.11
    - descr: lab scenario

lab-filter-rule:
  pfsense_filter_rule.present:
    - name: lab scenario rule
    - interface: lan
    - type: pass
    - ipprotocol: inet
    - protocol: tcp
    - source:
        address: 192.0.2.10
    - destination:
        address: 198.51.100.10
        port: '8443'

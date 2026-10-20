# Filter rules: order, floating rule, removal (recipe 11)
lan-to-dns:
  pfsense_filter_rule.present:
    - name: lan to resolver
    - interface: lan
    - index: 0
    - type: pass
    - protocol: tcp/udp
    - source:
        network: lan
    - destination:
        network: lanip
        port: '53'

block-bogus:
  pfsense_filter_rule.present:
    - name: block example network
    - floating: true
    - quick: true
    - direction: in
    - interface: wan
    - type: block
    - source:
        address: 198.51.100.0/24
    - destination:
        any: ''

old-rule:
  pfsense_filter_rule.absent:
    - name: old rule
    - interface: lan

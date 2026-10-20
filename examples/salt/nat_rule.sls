# Port forward (recipe 12)
https-forward:
  pfsense_nat_rule.present:
    - name: https to web server
    - protocol: tcp
    - target: 192.0.2.20
    - interface: wan
    - local_port: '443'
    - destination:
        network: wanip
        port: '443'

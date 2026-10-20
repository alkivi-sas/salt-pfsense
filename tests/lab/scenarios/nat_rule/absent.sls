lab-nat-rule:
  pfsense_nat_rule.absent:
    - name: lab scenario port forward
    - protocol: tcp
    - target: 192.0.2.20
    - interface: wan
    - local_port: '8443'
    - destination:
        network: wanip
        port: '18443'

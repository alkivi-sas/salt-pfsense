# VLAN and its interface (recipe 19)
voip-vlan:
  pfsense_vlan.present:
    - name: voip vlan
    - interface: igb1
    - tag: 20
    - descr: VOIP

voip-interface:
  pfsense_interface.present:
    - name: opt2
    - ifname: igb1.20
    - ipaddr: 10.0.20.1
    - subnet: 24
    - descr: VOIP
    - enable: true
    - require:
      - pfsense_vlan: voip-vlan

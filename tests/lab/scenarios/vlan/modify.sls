{% set parent = salt['pillar.get']('lab:vlan_parent', 'vtnet1') %}
lab-vlan:
  pfsense_vlan.present:
    - name: lab vlan
    - interface: {{ parent }}
    - tag: 3999
    - descr: lab scenario modified

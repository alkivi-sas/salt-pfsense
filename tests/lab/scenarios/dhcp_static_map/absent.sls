lab-static-map:
  pfsense_dhcp_static_map.absent:
    - name: lab static map
    - interface: lan
    - mac: 02:00:5e:00:53:01

lab-static-map-apply:
  pfsense_dhcp_static_map.apply:
    - name: apply

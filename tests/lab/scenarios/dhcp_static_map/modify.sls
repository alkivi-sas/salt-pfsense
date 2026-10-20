lab-static-map:
  pfsense_dhcp_static_map.present:
    - name: lab static map
    - interface: lan
    - mac: 02:00:5e:00:53:01
    - ipaddr: 192.168.1.251
    - hostname: lab-scenario

lab-static-map-apply:
  pfsense_dhcp_static_map.apply:
    - name: apply

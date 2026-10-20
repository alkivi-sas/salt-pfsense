# DHCP static mappings, committed once (recipe 18)
printer-map:
  pfsense_dhcp_static_map.present:
    - name: printer
    - interface: lan
    - mac: 02:00:5e:00:53:01
    - ipaddr: 192.168.1.50
    - hostname: printer
    - descr: printer

old-map:
  pfsense_dhcp_static_map.absent:
    - name: old printer
    - interface: lan
    - mac: 02:00:5e:00:53:02

static-maps-applied:
  pfsense_dhcp_static_map.apply:
    - name: apply

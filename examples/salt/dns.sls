# System DNS servers (recipe 20)
dns-quad9:
  pfsense_dns.present:
    - name: 9.9.9.9

dns-via-wan:
  pfsense_dns.present:
    - name: 1.1.1.1
    - gateway: WAN_DHCP

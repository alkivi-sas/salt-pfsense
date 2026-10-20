# OpenVPN client export of a user (recipe 16)
alice-openvpn-export:
  module.run:
    - pfsense_user.export_openvpn_config:
      - username: alice
      - addr: vpn.example.org
      - vpnid: 1
      - conf_type: confzip

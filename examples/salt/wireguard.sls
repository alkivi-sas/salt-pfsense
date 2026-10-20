# WireGuard peer (recipe 17)
laptop-peer:
  module.run:
    - pfsense_wireguard.add_peer:
      - name: laptop
      - tunnel: tun_wg0
      - publickey: ExamplePublicKeyOnlyForTheRecipe00000000000=
      - allowip: 10.6.0.2

# Kernel PPPoE (recipe 26): reboots the firewall when it changes
use-if-pppoe:
  module.run:
    - pfsense_if_pppoe.enable:
      - reboot: False

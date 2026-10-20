# First states of the firewall highstate (recipes 05 and 42)
pfrest-installed:
  pfsense_restapi.installed: []

pfrest-bootstrapped:
  pfsense_restapi.bootstrapped:
    - require:
      - pfsense_restapi: pfrest-installed

pfrest-configured:
  pfsense_restapi.configured:
    - require:
      - pfsense_restapi: pfrest-bootstrapped

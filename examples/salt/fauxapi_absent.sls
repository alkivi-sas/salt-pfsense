# Uninstall FauxAPI from a firewall fully on pfrest (recipe 46).
# Renders nothing while the firewall, or one of its modules, still uses the FauxAPI backend.
{% set backend = salt['pillar.get']('pfsense:api_backend', 'fauxapi') %}
{% set overrides = salt['pillar.get']('pfsense:api_backend_overrides', {}) %}
{% if backend == 'pfrest' and 'fauxapi' not in overrides.values() %}
fauxapi-package:
  cmd.run:
    - name: pkg delete -y pfSense-pkg-FauxAPI
    - onlyif: pkg info -e pfSense-pkg-FauxAPI

/etc/fauxapi:
  file.absent:
    - require:
      - cmd: fauxapi-package
{% endif %}

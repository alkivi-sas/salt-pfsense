{# Install and configure https://github.com/ndejong/pfsense_fauxapi #}

/tmp/pfSense-pkg-FauxAPI.txz:
  file.managed:
    - source: https://github.com/ndejong/pfsense_fauxapi/raw/master/package/pfSense-pkg-FauxAPI-1.2_2.txz
    - source_hash: sha256=aa01bd1750c325584291f7842ae7c0c20d9b82c9b5fa38bd79cce61c2f88031f

install-fauxapi:
  cmd.run:
    - name: pkg install -y /tmp/pfSense-pkg-FauxAPI.txz
    - unless: pkg info pfSense-pkg-FauxAPI | grep Version | grep 1.2_2
    - require:
      - file: /tmp/pfSense-pkg-FauxAPI.txz


/etc/fauxapi/credentials.ini:
  file.managed:
    - source: salt://pfsense/api/templates/credentials.ini.jinja
    - template: jinja
    - user: root
    - group: wheel
    - mode: 0600
    - require:
      - cmd: install-fauxapi

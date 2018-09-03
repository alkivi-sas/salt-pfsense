{% set customer = pillar.get('customer') %}

/home/restricted/pfsense/{{ customer }}-raw.xml:
  file.managed:
    - user: restricted
    - group: support
    - mode: 660
    - template: jinja
    - source: salt://pfsense/templates/config.xml.jinja
    - makedirs: True
    - dir_mode: 770
    - context:

/home/restricted/pfsense/{{ customer }}.xml:
  cmd.wait:
    - name: xmllint -format /home/restricted/pfsense/{{ customer }}-raw.xml > /home/restricted/pfsense/{{ customer }}.xml
    - watch:
      - file: /home/restricted/pfsense/{{ customer }}-raw.xml

chown:
  cmd.wait:
    - name: chown restricted /home/restricted/pfsense/{{ customer }}.xml
    - watch:
      - cmd: /home/restricted/pfsense/{{ customer }}.xml

chgrp:
  cmd.wait:
    - name: chgrp support /home/restricted/pfsense/{{ customer }}.xml
    - watch:
      - cmd: /home/restricted/pfsense/{{ customer }}.xml

chmod:
  cmd.wait:
    - name: chmod 660 /home/restricted/pfsense/{{ customer }}.xml
    - watch:
      - cmd: /home/restricted/pfsense/{{ customer }}.xml

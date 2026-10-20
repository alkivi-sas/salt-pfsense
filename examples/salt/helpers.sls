# PHP helpers used by the modules (recipe 03)
/opt/helpers:
  file.recurse:
    - source: salt://pfsense/files/helpers
    - include_pat: '*.php'
    - file_mode: '0700'
    - dir_mode: '0700'
    - user: root
    - group: wheel

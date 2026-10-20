# Local users and their SSH keys (recipes 13 and 14)
{% set users = salt['pillar.get']('users', {}) %}
{% for name, data in users.items() %}
user-{{ name }}:
  pfsense_user.present:
    - name: {{ name }}
    - descr: {{ data.get('descr', '') }}
    - password: {{ data.get('password_hash', '') }}
    - priv: {{ data.get('priv', []) }}
{% endfor %}

admin-key:
  pfsense_ssh_auth.present:
    - name: AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnlyForTheRecipe
    - user: admin
    - enc: ssh-ed25519
    - comment: admin@example.org

former-employee:
  pfsense_user.absent:
    - name: former.employee

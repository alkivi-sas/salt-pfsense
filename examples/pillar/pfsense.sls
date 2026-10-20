# Example pillar for a pfSense minion (recipes 04 to 07)
# Secrets come from an encrypted source: here the gpg renderer (#!yaml|gpg as first line).
pfsense:
  # Backend per firewall, then per module (recipe 06)
  api_backend: pfrest
  api_backend_overrides:
    pfsense_alias: fauxapi
  # immediate (default) or deferred: deferred needs pfsense_apply states (recipe 07)
  pfrest:
    apply: immediate
  restapi:
    # 64 hexadecimal characters: openssl rand -hex 32, stored encrypted (recipe 04)
    api_key: "<gpg encrypted, 64 hexadecimal characters>"
    settings: {}
    access_list:
      - network: 127.0.0.1/32
  # Subject of generated user certificates (recipe 15)
  pki:
    dn:
      country: FR
      state: Example
      city: Example
      organization: Example
  # DHCP options translated to Kea (recipe 18b)
  dhcp_kea:
    options:
      '43':
        name: unificontroller
        type: binary
        format: hex
      '132':
        name: yealink-vlan
        type: string
        always-send: true

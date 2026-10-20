# VPN user certificate, revocation (recipe 15)
alice-certificate:
  pfsense_user_cert.present:
    - name: alice

bob-revoked:
  module.run:
    - pfsense_certificate.revoke_user_certificate:
      - user: bob

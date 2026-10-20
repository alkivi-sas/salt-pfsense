# WebGUI alternative hostnames and settings (recipe 23)
vpn-hostname:
  pfsense_althostname.present:
    - name: vpn.example.org

no-dns-rebind-check:
  module.run:
    - pfsense_webgui_settings.set_setting:
      - name: nodnsrebindcheck
      - value: True

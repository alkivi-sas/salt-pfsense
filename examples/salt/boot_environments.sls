# Boot environments cleanup (recipe 27)
old-boot-environments:
  module.run:
    - pfsense_be.delete_be_for_version:
      - version: 26.03

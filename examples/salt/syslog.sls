# Remote syslog (recipe 21)
remoteserver:
  pfsense_syslog_configuration.present:
    - value: 198.51.100.5:5140

enable:
  pfsense_syslog_configuration.present:
    - value: True

format:
  pfsense_syslog_configuration.present:
    - value: rfc5424

logall:
  pfsense_syslog_configuration.present:
    - value: True

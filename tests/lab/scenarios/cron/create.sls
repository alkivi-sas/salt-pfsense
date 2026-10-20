lab-cron:
  pfsense_cron.present:
    - name: /usr/bin/true lab-scenario
    - identifier: lab-scenario
    - minute: 5
    - hour: 4

# Progressive rollout (recipe 40): run with salt-run state.orchestrate orch.rollout
{% set wave = salt['pillar.get']('rollout:targets', 'gateway.example-*') %}
check:
  salt.state:
    - tgt: '{{ wave }}'
    - sls: pfsense.restapi
    - test: True
    - batch: 1

apply:
  salt.state:
    - tgt: '{{ wave }}'
    - highstate: True
    - batch: '10%'
    - failhard: True
    - require:
      - salt: check

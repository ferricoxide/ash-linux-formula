# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-257811
# Rule ID:    SV-257811r942979_rule
# STIG ID:    RHEL-09-213080
# SRG ID:     SRG-OS-000132-GPOS-00067
#             SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must restrict usage of ptrace to descendant processes
#
# References:
#   - CCI:
#     - CCI-000366
#     - CCI-001082
#   - NIST:
#     - SP 800-53: CM-6 b
#     - SP 800-53: SC-2
#     - SP 800-53A: CM-6.1 (iv)
#     - SP 800-53A: SC-2.1
#     - SP 800-53 Rev 4: CM-6 b
#     - SP 800-53 Rev 4: SC-2
#     - SP 800-53 Rev 5: CM-6 b)
#     - SP 800-53 Rev 5: SC-2)
#
###########################################################################
{%- set stig_id = 'RHEL-09-213080' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFiles = [
    '/etc/sysctl.conf',
    '/etc/sysctl.d/99-sysctl.conf',
    '/lib/sysctl.d/10-default-yama-scope.conf',
    '/usr/lib/sysctl.d/10-default-yama-scope.conf'
  ]
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must restrict usage of
             `ptrace` to descendant processes
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for cfgFile in cfgFiles %}
Restrict usage of ptrace via {{ cfgFile }}:
  sysctl.present:
    - name: kernel.yama.ptrace_scope
    - value: 1
    - config:
  {%- endfor %}
{%- endif %}


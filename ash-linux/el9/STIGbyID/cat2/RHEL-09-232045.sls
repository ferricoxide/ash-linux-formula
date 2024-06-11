# Ref Doc:    STIG - RHEL 9 v1r3
# Finding ID: V-257889
# Rule ID:    SV-257889r925654_rule
# STIG ID:    RHEL-09-232045
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       All RHEL 9 local initialization files must have mode 0740 or less
#       permissive
#
# References:
#   - CCI:
#     - CCI-000366
#   - NIST:
#     - SP 800-53: CM-6 b
#     - SP 800-53A: CM-6.1 (iv)
#     - SP 800-53 Rev 4: CM-6 b
#     - SP 800-53 Rev 5: CM-6 b
#
###########################################################################
{%- set stig_id = 'RHEL-09-232045' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set localUserHomes = [] %}
{%- set localUserList = salt.user.list_users() %}
{%- set shell_inits = [] %}

# Construct list of unique home-directory paths
{%- for localUser in localUserList %}
  {%- set user_home = salt.user.info(localUser).home %}
  {%- if ( user_home != '/' ) and
         ( user_home != '/sbin' ) and
         ( user_home != '/bin' ) and
         ( user_home not in localUserHomes ) and
         ( '/var/spool' not in user_home )
  %}
    {%- do localUserHomes.append(user_home) %}
  {%- endif %}
{%- endfor %}

# Construct list of shell-init scripts found in iterated home-directory paths
{%- for homeDir in localUserHomes %}
  {%- for shell_init in salt.file.find(homeDir, type='f', name='.bash*') %}
    {%- do shell_inits.append(shell_init) %}
  {%- endfor %}
{%- endfor %}

# Correct permissions of shell-init scripts found in iterated home-directory paths
{%- for shell_init in shell_inits %}
Fixing mode on {{ shell_init }}:
  file.managed:
    - name: '{{ shell_init }}'
    - mode: '0740'
{%- endfor %}

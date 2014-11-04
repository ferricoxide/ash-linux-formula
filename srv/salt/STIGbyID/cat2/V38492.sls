# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38492
# Finding ID:	V-38492
# Version:	RHEL-06-000027
# Finding Level:	Medium
#
#     The system must prevent the root account from logging in from virtual 
#     consoles. Preventing direct root login to virtual console devices 
#     helps ensure accountability for actions taken on the system using the 
#     root account.
#
#  CCI: CCI-000770
#  NIST SP 800-53 :: IA-2 (5) (b)
#  NIST SP 800-53A :: IA-2 (5).2 (ii)
#  NIST SP 800-53 Revision 4 :: IA-2 (5)
#
############################################################

script_V38492-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38492.sh

file_V38492-repl:
  file.replace:
  - name: /etc/securetty
  - pattern: "^vc/"
  - repl: "# vc/"


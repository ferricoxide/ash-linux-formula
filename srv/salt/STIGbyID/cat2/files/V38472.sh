#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38472
# Finding ID:	V-38472
# Version:	RHEL-06-000048
# Finding Level:	Medium
#
#     All system command files must be owned by root. System binaries are 
#     executed by privileged users as well as system services, and 
#     restrictive permissions are necessary to ensure that their execution 
#     of these programs cannot be co-opted.
#
############################################################

# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------"
diag_out "  Ensure that all system binaries"
diag_out "  are not group- or world-writable"
diag_out "  All executables in:"
diag_out "  * /bin"
diag_out "  * /usr/bin"
diag_out "  * /usr/local/bin"
diag_out "  * /sbin"
diag_out "  * /usr/sbin"
diag_out "  * /usr/local/sbin"
diag_out "  Should be addressed."
diag_out "----------------------------------"
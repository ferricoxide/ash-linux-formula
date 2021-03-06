#!/bin/sh
# Finding ID:	RHEL-07-010160
# Version:	RHEL-07-010160_rule
# SRG ID:	SRG-OS-000072-GPOS-00040
# Finding Level:	medium
# 
# Rule Summary:
#	When passwords are changed a minimum of eight of the total
#	number of characters must be changed.
#
# CCI-000195 
#    NIST SP 800-53 :: IA-5 (1) (b) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (b) 
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "----------------------------------------"
diag_out "STIG Finding ID: RHEL-07-010160"
diag_out "   When passwords are changed a minimum"
diag_out "   of eight of the total number of"
diag_out "   characters must be changed."
diag_out "----------------------------------------"

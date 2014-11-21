#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51379
# Finding ID:	V-51379
# Version:	RHEL-06-000025
# Finding Level:	Low
#
#     All device files must be monitored by the system Linux Security 
#     Module. If a device file carries the SELinux type "unlabeled_t", then 
#     SELinux cannot properly restrict access to the device file.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

SELENFMODE=`/usr/sbin/getenforce`

case ${SELENFMODE} in
  Enforcing|Permissive) echo ${SELENFMODE}
     SETEXIT=0
     ;;
  Disabled) echo ${SELENFMODE}
     SETEXIT=1
     ;;
esac

if [ ${SETEXIT} -eq 1 ]
then
   printf "SELinux disabled: cannot check FS labeling\n"

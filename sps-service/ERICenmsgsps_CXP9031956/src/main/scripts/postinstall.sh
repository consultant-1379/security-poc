#!/bin/sh

logger "Running Service Group RPM postinstall"

_LOGGER=/bin/logger
_SCRIPT_NAME="${0}"
_SED=/bin/sed
_SETENFORCE=/usr/sbin/setenforce
_SWAPOFF=/sbin/swapoff
_ECHO=/bin/echo
_SYSTEMCTL=/bin/systemctl
_JBOSSSERVICE=/usr/lib/systemd/system/jboss.service

readonly swappiness=/proc/sys/vm/swappiness

#These variables are used to reserve the cache ports in SPS SG
readonly SYSCTL="/sbin/sysctl"
readonly LOG_TAG="SPS_POSTINSTALL"
readonly RESERVED_PORTS_FOR_SPS="56400,56401,56402,56406,56407,56408,56412,56413,56414,56418,56419,56420"

error()
{
  $_LOGGER -t "${LOG_TAG}" -p user.err "( ${SCRIPT_NAME} ): $1"
}

info()
{
  $_LOGGER -t "${LOG_TAG}" -p user.info "( ${SCRIPT_NAME} ): $1"
}

disable_swap ()
{
info "Disabling swap on KVM"

if ! $_SED -i '/swap/d' /etc/fstab; then
  error "Failed to remove swap entry from fstab"
fi

if ! $_SWAPOFF -a; then
  error "Failed to disable swapping. Command that failed : '$_SWAPOFF -a'"
fi

if ! $_ECHO 0 > $swappiness; then
  error "Failed to set swappiness to 0."
fi

}

change_fs_permissons ()
{
_TIMEOUT_=300
_INIT_=0
while [ $_INIT_ -lt $_TIMEOUT_ ]; do
  ARRAY_FS=(/ericsson/pmic /ericsson/symvol /ericsson/enm/dumps /ericsson/batch /ericsson/config_mgt)
  for _FS_ in "${ARRAY_FS[@]}"; do
    if [ -d $_FS_ ]; then
      username=`/bin/ls -ld $_FS_ | awk '{print $3}'`
      if [ $username != jboss_user ]; then
        /bin/chown jboss_user:jboss $_FS_
		logger "Changed permission of $_FS_"
      fi
    fi
  done
sleep 1
((_INIT_++))
done
}

###################################################################################
#
# Purpose: Reserve local ports for PKICoreMastershipCluster,PKIMastershipCluster,
# PkiWebCliExportCache,SupportedAlgorithmsCache in SPS SG
#
# You can verify the expected result of running the script as follows:
# Command:
# sudo sysctl -n net.ipv4.ip_local_reserved_ports
# The result should contain:
# 56400,56401,56402,56406,56407,56408,56412,56413,56414,56418,56419,56420
###################################################################################
function ports_reserve_for_sps ()
{
   reserved_ports=$($SYSCTL -n net.ipv4.ip_local_reserved_ports)

   if [[ -z "${reserved_ports// }" ]]; then
     reserved_ports=${RESERVED_PORTS_FOR_SPS}
   else
     reserved_ports+=",${RESERVED_PORTS_FOR_SPS}"
   fi

   if $SYSCTL -w net.ipv4.ip_local_reserved_ports=${reserved_ports}; then
     logger -s -t ${LOG_TAG} -p user.info "Reserved the following ports in SPS SG for PKICoreMastershipCluster,PKIMastershipCluster,PkiWebCliExportCache,SupportedAlgorithmsCache: ${RESERVED_PORTS_FOR_SPS}"
   else
     logger -s -t ${LOG_TAG} -p user.err "Failed to reserve the following ports in SPS SG for PKICoreMastershipCluster,PKIMastershipCluster,PkiWebCliExportCache,SupportedAlgorithmsCache: ${RESERVED_PORTS_FOR_SPS}"
   fi
}

function extend_sysctl_online_timeout ()
{
    if [ -f "${_JBOSSSERVICE}" ] && [ -f "${_SYSTEMCTL}" ]; then
        ${_SED} -i '/^\[Service\]$/,/^\[/ s/^[ \t]*TimeoutStartSec.*/TimeoutStartSec=240min/' "${_JBOSSSERVICE}"
        ${_SYSTEMCTL} daemon-reload
        logger -s -t "${LOG_TAG}" -p user.info "systemctl TimeoutStartSec updated to 240 minutes"
    fi
}

disable_swap

extend_sysctl_online_timeout

#Chkconfig jboss on and start

logger "Running change_fs_permissions in background"
change_fs_permissons &

logger "Running credentialmanagercliconfig in background"
/ericsson/enm/sps_cliconf/credentialmanagercliconfig.sh & 

#Reserve the cache ports for SPS
logger "Running ports_reserve_for_sps in background"
ports_reserve_for_sps

logger "SPS Service postinstall completed"
exit 0

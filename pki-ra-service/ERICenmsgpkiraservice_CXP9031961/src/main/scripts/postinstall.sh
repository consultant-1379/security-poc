#!/bin/bash
###########################################################################
# COPYRIGHT Ericsson 2017
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
###########################################################################
#
# Purpose: Reserve local ports for PKIRASCEPMastershipCluster,PKIRAMastershipCluster,
# ScepCrlCache,CRLCache and CMPServiceTransactionCluster in PKIRASERV SG
#
# You can verify the expected result of running the script as follows:
# Command:
# sudo sysctl -n net.ipv4.ip_local_reserved_ports
# The result should contain:
# 56403,56404,56405,56409,56410,56411,56415,56416,56417,56450,56451,56452,56456,56457,56458
###########################################################################

logger "Running pki-ra-service postinstall"


readonly SYSCTL="/sbin/sysctl"
readonly LOG_TAG="PKIRASERV_POSTINSTALL"
readonly RESERVED_PORTS_FOR_PKIRASERV="56403,56404,56405,56409,56410,56411,56415,56416,56417,56450,56451,56452,56456,56457,56458"

function ports_reserve_for_pkiraserv ()
{
	reserved_ports=$($SYSCTL -n net.ipv4.ip_local_reserved_ports)

	if [[ -z "${reserved_ports// }" ]]; then
		reserved_ports=${RESERVED_PORTS_FOR_PKIRASERV}
	else
		reserved_ports+=",${RESERVED_PORTS_FOR_PKIRASERV}"
	fi

	if $SYSCTL -w net.ipv4.ip_local_reserved_ports=${reserved_ports}; then
		logger -s -t ${LOG_TAG} -p user.info "Reserved the following ports in PKIRASERV SG for PKIRASCEPMastershipCluster,PKIRAMastershipCluster,ScepCrlCache,CRLCache and CMPServiceTransactionCluster: ${RESERVED_PORTS_FOR_PKIRASERV}"
	else
		logger -s -t ${LOG_TAG} -p user.err "Failed to reserve the following ports in PKIRASERV SG for PKIRASCEPMastershipCluster,PKIRAMastershipCluster,ScepCrlCache,CRLCache and CMPServiceTransactionCluster: ${RESERVED_PORTS_FOR_PKIRASERV}"
	fi
}

###########################################################################
#
# Purpose: This script is responsible to turn the swap off for PKIRASERV SG
#
# The result of the script can be verified in PKIRASERV SG as follows:
# Command:
# sar 1 5 -S
# The result should contain:
# kbswpfree kbswpused  %swpused  kbswpcad   %swpcad
#    0         0         0.00        0        0.00
###########################################################################

function swapoff_for_pkiraserv ()
{
_SWAPOFF=/sbin/swapoff
_LOGGER=/bin/logger
SCRIPT_NAME="${0}"
_ECHO=/bin/echo
readonly swappiness=/proc/sys/vm/swappiness
	error()
	{
	  $_LOGGER -t "${LOG_TAG}" -p user.err "( ${SCRIPT_NAME} )"
	}

	info()
	{
	  $_LOGGER -t "${LOG_TAG}" -p user.notice "( ${SCRIPT_NAME} )"
	}

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

#Reserve the cache ports for PKIRASERV
echo "Running ports_reserve_for_pkiraserv"
ports_reserve_for_pkiraserv
echo "Running swapoff for pkiraserv"
swapoff_for_pkiraserv

logger "pki-ra-service postinstall completed"
exit 0

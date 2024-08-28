#!/bin/bash
##########################################################################
# COPYRIGHT Ericsson 2018
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
###########################################################################
#
# This script should be executed as a jboss pre_stop in PKIRA service group
#
################################################
#  Variables
################################################
readonly DDC_DATA_PATH="/var/ericsson/ddc_data/$(hostname)_TOR/config"

logger -t PKIRASERV_CACHE "verifying the stateTransferInProgress value for PKIRA caches"

rep_state=`timeout 5s /opt/ericsson/ERICddc/util/bin/instr -defaultPollInterval 1 -maxtime 3 -metrics $DDC_DATA_PATH/CrlCacheConfig.xml | awk '/cache-CrlCache-state/ && /true|false/{ print $4 }'`
logger -t PKIRA_CRL_CACHE "stateTransferInProgress is $rep_state"

while [ -n "$rep_state" ] && $rep_state
do
        rep_state=`timeout 5s /opt/ericsson/ERICddc/util/bin/instr -defaultPollInterval 1 -maxtime 3 -metrics $DDC_DATA_PATH/CrlCacheConfig.xml | awk '/cache-CrlCache-state/ && /true|false/{ print $4 }'`
        logger -t PKIRA_CRL_CACHE "stateTransferInProgress is again $rep_state"
done

logger -t PKIRA_CRL_CACHE "stateTransferInProgress before exit $rep_state"

rep_state=`timeout 5s /opt/ericsson/ERICddc/util/bin/instr -defaultPollInterval 1 -maxtime 3 -metrics $DDC_DATA_PATH/ScepCrlCacheConfig.xml | awk '/cache-ScepCrlCache-state/ && /true|false/{ print $4 }'`
logger -t PKIRA_SCEP_CRL_CACHE "stateTransferInProgress is $rep_state"

while [ -n "$rep_state" ] && $rep_state
do
        rep_state=`timeout 5s /opt/ericsson/ERICddc/util/bin/instr -defaultPollInterval 1 -maxtime 3 -metrics $DDC_DATA_PATH/ScepCrlCacheConfig.xml | awk '/cache-ScepCrlCache-state/ && /true|false/{ print $4 }'`
        logger -t PKIRA_SCEP_CRL_CACHE "stateTransferInProgress is again $rep_state"
done

logger -t PKIRA_SCEP_CRL_CACHE "stateTransferInProgress before exit $rep_state"

exit
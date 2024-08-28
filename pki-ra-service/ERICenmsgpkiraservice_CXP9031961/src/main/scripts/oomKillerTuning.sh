#!/bin/bash
#########################################################################
# COPYRIGHT Ericsson 2019
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
#########################################################################


VM_SUBSYSTEM_CONFIG_DIR=/proc/sys/vm


#######################################
# Action :
#   Set VM subsystem configuration.
# Globals :
#   VM_SUBSYSTEM_CONFIG_DIR
# Arguments:
#   configParam - VM configuration parameter to set
#   configParamValue - VM configuration parameter value
# Returns:
#   None
#######################################
set_vm_subsytem_config_param (){
    local configParam=$1
    local configParamValue=$2
    local configFilePath="${VM_SUBSYSTEM_CONFIG_DIR}/${configParam}"

    if [ -f "$configFilePath" ] ; then
        echo $configParamValue > $configFilePath
        if [ $? -eq 0 ];  then
           logger "Successfully set $configParam to $configParamValue"
           return;
        fi
    fi

    logger "Failed to set $configParam to $configParamValue"
}

#Execution Starting from here

set_vm_subsytem_config_param "min_free_kbytes" "131072"


##################################################################################################################
# By setting overcommit_memory to 2 we are telling the kernel to be precise about the overcommit. Never
# commit a virtual address space larger than swap space plus a fraction "overcommit_ratio" of the physical memory
##################################################################################################################

set_vm_subsytem_config_param "overcommit_memory" "2"


##########################################################################################
# Setting overcomiit_ratio to 100 ensure we never try use memory that is not available.
##########################################################################################

set_vm_subsytem_config_param "overcommit_ratio" "100"
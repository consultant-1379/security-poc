#!/bin/bash

# UTILITIES
_GETSEBOOL=/usr/sbin/getsebool
_GREP=/bin/grep
_RESTORECON=/sbin/restorecon
_RSYNC=/usr/bin/rsync
_SEMANAGE=/usr/sbin/semanage
_SETSEBOOL=/usr/sbin/setsebool
_STAT=/usr/bin/stat

# GLOBAL VARIABLES
SCRIPT_NAME="${0}"
LOG_TAG="SPS_CONFIG"
SOURCE_DIR='/ericsson/enm/sps_cliconf'
CACHE_SHARE='/ericsson/sps/data'
DESTINATION_DIR=$CACHE_SHARE/$(hostname)'_TOR/cache-config'
SUPPORTED_ALGORITHMS_CACHE_CONFIG_XML="SupportedAlgorithmsCacheConfig.xml"
PKI_WEB_CLI_EXPORT_CACHE_CONFIG_XML="PkiWebCliExportCacheConfig.xml"
MAX_TIME_TO_WAIT=60

#######################################
# This function will print an info message to /var/log/messages
# Arguments:
#             $1 - Message
# Return: 0
#######################################
info(){
    logger -t ${LOG_TAG} -p user.info "( ${SCRIPT_NAME} ): $1"
}

#######################################
# This function will print a warning message to /var/log/messages
# Arguments:
#             $1 - Message
# Return: 0
#######################################
warn(){
    logger -t ${LOG_TAG} -p user.warning "( ${SCRIPT_NAME} ): $1"
}

#######################################
# This function will print a error message to /var/log/messages
# Arguments:
#             $1 - Message
# Return: 0
#######################################
error(){
    logger -t ${LOG_TAG} -p user.error "( ${SCRIPT_NAME} ): $1"
}

#######################################
# Action :
#    Confirm SELinux is for configured as
#    expected for rsync
# Globals :
#     SOURCE_DIR
# Arguments:
#     None
# Returns:
#
#######################################
setup_selinux() {
    info "SELinux: Changing security context of $SOURCE_DIR/"
    $_SEMANAGE fcontext -a -t rsync_data_t "$SOURCE_DIR/$1"
    $_RESTORECON -R $SOURCE_DIR

    if $_GETSEBOOL rsync_use_nfs | $_GREP off$; then
        info "SELinux: Allowing rsync to access nfs"
        $_SETSEBOOL -P rsync_use_nfs 1
    fi
}

#######################################
# Action :
#    Creates CACHE_SHARED directories
# Globals :
#     CACHE_SHARE
# Arguments:
#     None
# Returns:
#
#######################################
create_cache_shared_dirs() {
   if [ ! -d "$DESTINATION_DIR" ]; then
   info   "CACHE SHARED DIRECTORY DOESN'T EXISTS AND CREATING DIRECTORY >>>>>>>>> $CACHE_SHARE"
   mkdir -p "$DESTINATION_DIR";
   fi
}

#######################################
# Action :
#    Checks For  CACHE_SHARED Directory existance and creates
# Globals :
#     CACHE_SHARE
# Arguments:
#     None
# Returns:
#
########################################
precheck_for_cache_shared_dir() {
    retry_wait=1
    while [ ! -d "$DESTINATION_DIR" ]; do
        echo "$DESTINATION_DIR IS NOT CREATED YET - sleeping $retry_wait seconds"
        sleep $retry_wait
        retry_wait=$((retry_wait+1))

        if [ $retry_wait -gt $MAX_TIME_TO_WAIT ]; then
            error "Exiting - $DESTINATION_DIR NOT CREATED in $MAX_TIME_TO_WAIT seconds"
            exit 0
        fi
    done
}

#######################################
# Action :
#    Copy Files to CACHE_SHARED
#    All metadata files in SOURCE_DIR are
#    copied to DESTINATION_DIR.
# Globals :
#     SOURCE_DIR
#     DESTINATION_DIR
# Arguments:
#     None
# Returns:
#
#######################################
copy_files_to_shared() {
    sleep_time=1
    total_sleep_time=0
    while ! $_RSYNC -craz "$SOURCE_DIR/$1" "$DESTINATION_DIR/$1"; do
        warn "Copy to $CACHE_SHARE failed - retrying"
        sleep $sleep_time
        total_sleep_time=$(($total_sleep_time+$sleep_time))

        if [ $total_sleep_time -gt $MAX_TIME_TO_WAIT ]; then
            error "Exiting - $SOURCE_DIR/$1 has not been copied to $DESTINATION_DIR/$1 in $MAX_TIME_TO_WAIT seconds"
            exit 0
        fi
    done
}

#######################################
# Main
#######################################

# Check for Source File
if [ ! -f "$SOURCE_DIR/$SUPPORTED_ALGORITHMS_CACHE_CONFIG_XML" ] || [ ! -f "$SOURCE_DIR/$PKI_WEB_CLI_EXPORT_CACHE_CONFIG_XML" ]; then
    warn "Cache Config XML does not exist - exiting"
    exit 0
fi


setup_selinux $SUPPORTED_ALGORITHMS_CACHE_CONFIG_XML
setup_selinux $PKI_WEB_CLI_EXPORT_CACHE_CONFIG_XML

create_cache_shared_dirs

precheck_for_cache_shared_dir

copy_files_to_shared $SUPPORTED_ALGORITHMS_CACHE_CONFIG_XML
copy_files_to_shared $PKI_WEB_CLI_EXPORT_CACHE_CONFIG_XML
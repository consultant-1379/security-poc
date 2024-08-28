##########################################################################
# COPYRIGHT Ericsson 2020
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##########################################################################

# Ensure script is sourced
[[ "${BASH_SOURCE[0]}" = "$0" ]] && { echo "ERROR: script $0 must be sourced, NOT executed"; exit 1; }

#*****************************************************************************#
# Log messages using infoLog function
#*****************************************************************************#

#*****************************************************************************#
# This function is used for logging all the info and errors
#*****************************************************************************#
function infoLog(){
    local LDATE=$(date +[%m%d%Y%T])
    msg="$1"
    logger -s ${LOG_FILE} "${msg}"
    echo "$LDATE $msg" &>>$INSTALL_LOG_DIR/$LOG_FILE
}

function info() {
	infoLog "INFO: $1"
}

function warning() {
	infoLog "WARNING: $1"
}

function error() {
	infoLog "ERROR: $1"
}

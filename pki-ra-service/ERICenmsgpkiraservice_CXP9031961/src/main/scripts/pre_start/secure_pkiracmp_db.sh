###########################################################################
# COPYRIGHT Ericsson 2020
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
# This script requires bash 4 or above
#
###########################################################################

DATABASE_SCRIPT=/ericsson/pki_postgres/db/pkiracmp/install_update_pkiracmp_db.sh
SCRIPT_NAME="${BASENAME} ${0}"

#############################################################
#
# Logger Functions
#
#############################################################
info()
{
    logger -t "${LOG_TAG}" -p user.notice "INFO (${SCRIPT_NAME} ): $1"
}

error()
{
    logger -t "${LOG_TAG}" -p user.err "ERROR (${SCRIPT_NAME} ): $1"
}

#MAIN

info "Checking if pkiracmp postgres database is up to date and running..."

$DATABASE_SCRIPT
if [ $? -ne 0 ]; then
    error "Error occured when checking pkiracmp postgres database."
    exit 1
fi
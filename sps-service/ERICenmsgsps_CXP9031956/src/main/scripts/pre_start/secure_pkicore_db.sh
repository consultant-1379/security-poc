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

DATABASE_SCRIPT=/ericsson/pki_postgres/db/pkicore/install_update_pkicore_db.sh
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

info "Checking if pkicore postgres database is up to date and running..."

source /ericsson/pki_postgres/db/common/lib/pg_utilities_library.sh

pgIsReady
if [ $? -ne 0 ]; then
    error "Postgres is not ready while checking pkicore postgres database."
    exit 1
fi

$DATABASE_SCRIPT
if [ $? -ne 0 ]; then
    error "Error occured when checking pkicore postgres database."
    exit 1
fi

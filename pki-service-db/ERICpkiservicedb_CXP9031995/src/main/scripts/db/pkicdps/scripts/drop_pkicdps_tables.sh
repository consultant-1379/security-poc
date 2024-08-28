#!/bin/bash
##########################################################################
# COPYRIGHT Ericsson 2016
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
###########################################################################
# Pre-requisite : Database pkicdpsDb with tables is already created
###########################################################################

source /ericsson/pki_postgres/db/pkicdps/config/pkicdpsdb.config
source /ericsson/pki_postgres/db/pkicdps/lib/db-shared-library.sh

##MAIN
fetchPostgresPassword
applySchema $DB $DDLS_PATH/drop.tables.ddl
checkExitCode "Dropping pkicdpsdb database tables"
unsetPassword

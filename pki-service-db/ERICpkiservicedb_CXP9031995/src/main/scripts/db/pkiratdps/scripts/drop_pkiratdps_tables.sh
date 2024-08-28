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
# Pre-requisite : Database pkiratdpsDb with tables is already created
###########################################################################

source /ericsson/pki_postgres/db/pkiratdps/config/pkiratdpsdb.config
source /ericsson/pki_postgres/db/pkiratdps/lib/db-shared-library.sh

##MAIN
fetchPostgresPassword
applySchema $DB $DDLS_PATH/drop.tables.ddl
checkExitCode "Dropping pkiratdpsdb database tables"
unsetPassword

#!/bin/bash
##########################################################################
# COPYRIGHT Ericsson 2016
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##########################################################################

source /ericsson/pki_postgres/db/pkirascep/config/pkirascepdb.config
source /ericsson/pki_postgres/db/pkirascep/lib/db-shared-library.sh
source /ericsson/pki_postgres/db/pkirascep/lib/postgres01.config


#*****************************************************************************#
#This function drops the pkirascepdb database,if database exists in pg_database
#*****************************************************************************#
function drop_db(){
    infoLog "dropping ${DB} db"
    DB_TEST=${TMP_DIR}/${DB}_test
    local LDATE=`date +[%Y-%m-%dT%H:%M:%S:%N]`
    if ls ${DB_TEST}* 1>/dev/null 2>&1; then
        find ${DB_TEST}* -mtime +7 -exec rm -rf {} \;
    fi

    PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 1>${DB_TEST}.${LDATE} 2>/dev/null
    SELECT * FROM pg_database WHERE datname = '${DB}';
EOF
    checkExitCode "Checking whether ${DB} exists in pg_database"

    is_db_pkirascepdb=`grep -i ${DB} ${DB_TEST}.${LDATE} | wc -l`

    if [ ${is_db_pkirascepdb} -gt 0 ]; then
          infoLog "dropping ${DB} database"
          PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
          DROP DATABASE ${DB};
EOF
    else
          infoLog "database ${DB} does not exists"
    fi
    checkExitCode "Dropping database ${DB}, if database exists in pg_database"
}


##MAIN
fetchPostgresPassword
drop_db
unsetPassword


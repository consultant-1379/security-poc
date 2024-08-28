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

source /ericsson/pki_postgres/db/pkimanager/lib/postgres01.config
source /ericsson/pki_postgres/db/pkimanager/config/pkimanagerdb.config
source /ericsson/pki_postgres/db/pkimanager/lib/db-shared-library.sh

#*****************************************************************************#
# This method reads and returns the connection limit value for a particular
# database in postgresql. If the connection limit value is zero, it reports
# error situation probably caused due to previous session failure in resetting
# the connection limit value.
#
# $1 refers to database name
#*****************************************************************************#
function readDBConnectionLimit(){
        database=$1

        infoLog "Reading connection limit value for database : ${database}"

        conn_limit=`PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U ${PG_USER} -h${HOSTNAME} -d ${database} -Atc "SELECT datconnlimit FROM pg_database where datname='${database}'"`;
        checkExitCode "Reading connection limit for database : ${database}"

        if [ ${conn_limit} -eq 0 ]; then
        infoLog "Connection limit value is zero in ${database} database,probably error might have encountered in resetting connection limit to original value in previous session"

        infoLog "Resetting connection limit value to default unlimited connections i.e. '-1' in ${database} database."
        conn_limit=-1
        fi
        checkExitCode "Checking connection limit value for database : ${database}"

        echo $conn_limit

}

#*****************************************************************************#
# This method stops accepting new connection requests to a given database in
# order to perform database upgrade operation.
#
# $1 refers to database name
#*****************************************************************************#
function stopAcceptingNewDBConnectionRequests(){
        database=$1

        infoLog "About to stop accepting new DB connection requests to database : ${database}"

        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>>${INSTALL_LOG_DIR}/${LOG_FILE}
        ALTER DATABASE ${database} CONNECTION LIMIT 0;
EOF
        checkExitCode "Stop accepting new DB connection requests to database : ${database}"
        infoLog "Stopped accepting new DB connection requests to database : ${database}"

}

#*****************************************************************************#
# This method waits for ongoing transactions on all the tables to complete
# before proceeding with database upgrade operation.
#
# $1 refers to time to sleep in seconds
#*****************************************************************************#
function waitForCompletionOfOngoingTransactions(){
        time_to_wait=$1

        infoLog "Waiting for $time_to_wait seconds to let ongoing transactions complete"

        sleep $time_to_wait
        checkExitCode "Waiting for $time_to_wait seconds to let ongoing transactions complete"

}

#*****************************************************************************#
# This method kills any ongoing transactions on requested table for successful
# completion of upgrade operation on the table
#
# $1 refers to database name
# $2 refers to upgrading table
#*****************************************************************************#
function killOngoingTransOnTable(){
        database=$1
        upgrading_table=$2

        infoLog "About to call 'kill_ongoing_trans_on_table' function on database $database"

        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d${database} <<EOF 2>>${INSTALL_LOG_DIR}/${LOG_FILE}
        BEGIN;
        select kill_ongoing_trans_on_table('$upgrading_table');
        COMMIT;
EOF
        checkExitCode "Calling 'kill_ongoing_trans_on_table' function on database $database"

}

#*****************************************************************************#
# This method resumes accepting new connections to a given database by resetting
# the connection limit value to original one.
#
# $1 refers to database name
# $2 refers to original connection limit value for that database
#*****************************************************************************#
function resumeAcceptingNewDBConnections(){
        database=$1
        con_limit=$2

        infoLog "About to resume accepting new connections to database : ${database} by resetting connection limit value to '${con_limit}'"

        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>>${INSTALL_LOG_DIR}/${LOG_FILE}
        ALTER DATABASE ${database} CONNECTION LIMIT $con_limit;
EOF
        checkExitCode "Resume accepting new connections to database : ${database} by resetting connection limit value to '${con_limit}'"
        infoLog "Resumed accepting new connections to database : ${database} by resetting connection limit value to '${con_limit}'"

}

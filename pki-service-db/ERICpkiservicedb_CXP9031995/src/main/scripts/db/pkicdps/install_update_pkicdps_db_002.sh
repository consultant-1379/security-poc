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

###########################################################################
# This script should be executed as a pki-ra-cdps post-install script in
# order to create schema for the pkicdpsdb.
#
# Pre-requisite : Database pkicdpsdb is already created
###########################################################################

source /ericsson/pki_postgres/db/pkicdps/config/pkicdpsdb.config
source /ericsson/pki_postgres/db/common/lib/pg_log_library.sh
source /ericsson/pki_postgres/db/pkicdps/lib/db-shared-library.sh
source /ericsson/pki_postgres/db/pkicdps/lib/postgres01.config
source /ericsson/enm/pg_utils/lib/pg_dblock_library.sh
source /ericsson/enm/pg_utils/lib/pg_dbcreate_library.sh

###########################################################################
# Variable
###########################################################################
CURRENT_VERSION=0.0.0

#*****************************************************************************#
# This method checks for existence of db_version table and fetches the current
# version value of database from db_version table. Using this current version,
# next version of upgrade will be triggered
#*****************************************************************************#
function evaluateCurrentDBVersion() {

    isTableExists $DB $DB_VERSION_TABLE
    is_db_version_table=$?
    if [ ${is_db_version_table} -gt 0 ]; then
        infoLog "${DB_VERSION_TABLE} table already exists in ${DB} database"
        CURRENT_VERSION=`PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U ${PG_USER} -h${HOSTNAME} -d ${DB} -Atc "SELECT version FROM ${DB_VERSION_TABLE} WHERE STATUS = 'current'"`;
    else
        infoLog "need to create ${DB_VERSION_TABLE} table in ${DB} database"
        CURRENT_VERSION=0.0.0
    fi
    checkExitCode "Current db version value from ${DB_VERSION_TABLE} table in ${DB} database is : ${CURRENT_VERSION}"
}


#*****************************************************************************#
# In this method, pki-ra-tdps database will be installed or upgraded with roles,
# tables and default values depending on current version value which is fetched
# from db_version table.
#*****************************************************************************#
function installUpgradeDB() {
    case "${CURRENT_VERSION}" in
        "0.0.0") echo "Installing default version 1.0.0"
                createRole $DB $DB_ROLE
                applySchema $DB $DDLS_PATH/create.tables.ddl
                applySchema $DB $DDLS_PATH/create.dbversion.ddl
                applySchema $DB $DDLS_PATH/insert.dbversion.ddl
                checkExitCode "Creating all required tables with default values in pkicdpsdb database for version 1.0.0 finished successfully"
                ;&
        "1.0.0") echo "Upgrading to version 2.0.0"
                revokeSuperUserPermissions $DB_ROLE
                createGroupAndAddRoleToGroup $DB $DB_GROUP $DB_ROLE
                applySchema $DB $DDLS_PATH/alter.schema.owner.ddl
                revokeDbPermissions $DB $DB_GROUP
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.0.0.ddl
                checkExitCode "Revoking super user permissions for pkicdps role, creating pkicdpsgrp group and revoking public connections on pkicdpsdb database in version 2.0.0"
                ;&
    esac
}

function lock_db() {
    PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) PG_CLIENT=${PG_ROOT}/psql PG_HOSTNAME=${HOSTNAME} lockDb "$@"
}

function unlock_db() {
    PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) PG_CLIENT=${PG_ROOT}/psql PG_HOSTNAME=${HOSTNAME} unlockDb "$@"
    unsetPassword
}

function create_db() {
	local PGPASSWORD=$(cat ${FILE_DIR}/${FILE})
	local PG_CLIENT=${PG_ROOT}/psql
	local PG_HOSTNAME=${HOSTNAME}
	local PG_DBCREATE_OPT="WITH ENCODING = 'UTF8' TABLESPACE = pg_default CONNECTION LIMIT = -1"
	createDb
}


#Main
logRotate
fetchPostgresPassword
create_db
checkExitCode "Create $DB"
lock_db
checkExitCode "Acquired lock on $DB"
trap 'unlock_db $DB_LOCK_OWNER' EXIT
evaluateCurrentDBVersion
installUpgradeDB

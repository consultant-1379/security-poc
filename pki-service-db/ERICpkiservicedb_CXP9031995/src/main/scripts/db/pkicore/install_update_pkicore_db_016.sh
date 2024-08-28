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
# This script should be executed on DB node in order to create schema
# for the pkicoredb.
#
# Pre-requisite : Database pkicore is already created
###########################################################################

source /ericsson/pki_postgres/db/pkicore/config/pkicoredb.config
source /ericsson/pki_postgres/db/common/lib/pg_log_library.sh
source /ericsson/pki_postgres/db/pkicore/lib/db-shared-library.sh
source /ericsson/pki_postgres/db/pkicore/lib/db-upgrade-shared-library.sh
source /ericsson/pki_postgres/db/pkicore/lib/postgres01.config
source /ericsson/enm/pg_utils/lib/pg_dblock_library.sh
source /ericsson/enm/pg_utils/lib/pg_dbcreate_library.sh

###########################################################################
# Variable
###########################################################################
CURRENT_VERSION=0.0.0

#*****************************************************************************
# This method checks for existence of db_version table and fetches the current
# version value of database from db_version table. Using this current version,
# next version of upgrade will be triggered
#*****************************************************************************
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


#*****************************************************************************
# In this method, pki-core database will be installed or upgraded with roles,
# tables and default values depending on current version value which is fetched
# from db_version table.
#*****************************************************************************
function installUpgradeDB() {

    if [ "$CURRENT_VERSION" = "0.0.0"  ];
    then
        applySchema $DB $DDLS_PATH/drop.old.model.tables.ddl

    elif [ "$CURRENT_VERSION" = "1.0.0"  ]
    then
        applySchema $DB $DDLS_PATH/drop.tables.ddl

    fi

    case "${CURRENT_VERSION}" in
        "0.0.0" | "1.0.0") echo "Installing default version 1.0.0"
                createRole $DB $DB_ROLE
                applySchema $DB $DDLS_PATH/create.tables.ddl
                applySchema $DB $DDLS_PATH/insert.defaultdata.ddl
                applySchema $DB $DDLS_PATH/create.dbversion.ddl
                applySchema $DB $DDLS_PATH/insert.dbversion.ddl
                checkExitCode "Creating all required tables with default values in pkicoredb database for version 1.0.0"
                ;&

        "1.1.0") echo "Upgraded to version 2.0.0"
                applySchema $DB $DDLS_PATH/update.tables_2.0.0.ddl
                applySchema $DB $DDLS_PATH/insert.defaultdata_2.0.0.ddl
                applySchema $DB $DDLS_PATH/insert.dbversion_2.0.0.ddl
                checkExitCode "Creating all required tables with default values in pkicoredb database for version 2.0.0"
                ;&

        "2.0.0") echo "Upgraded to version 2.1.0"
                applySchema $DB $DDLS_PATH/update.tables_2.1.0.ddl
                applySchema $DB $DDLS_PATH/insert.dbversion_2.1.0.ddl
                checkExitCode "Creating all required tables with default values in pkicoredb database for version 2.1.0"
                ;&

        "2.1.0") echo "Upgraded to version 2.2.0"
                applySchema $DB $DDLS_PATH/update.tables_2.2.0.ddl
                applySchema $DB $DDLS_PATH/insert.dbversion_2.2.0.ddl
                checkExitCode "Creating all required tables with default values in pkicoredb database for version 2.2.0"
                ;&

        "2.2.0") echo "Upgraded to version 2.3.0"
                revokeSuperUserPermissions $DB_ROLE
                createGroupAndAddRoleToGroup $DB $DB_GROUP $DB_ROLE
                applySchema $DB $DDLS_PATH/alter.schema.owner.ddl
                revokeDbPermissions $DB $DB_GROUP
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.3.0.ddl
                checkExitCode "Revoking super user permissions for pkicore role and revoked public connections on pkicoredb database in version 2.3.0"
                ;&
        "2.3.0") echo "Upgraded to version 2.4.0"
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.defaultdata_2.4.0.ddl
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.4.0.ddl
                checkExitCode "New Algorithm ECDSA 521 Added to algorithm table on pkicoredb database in version 2.4.0"
                ;&
        "2.4.0") echo "Upgraded to version 2.5.0"
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/update.tables_2.5.0.ddl
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.5.0.ddl
                checkExitCode "Added new column is_issuer_external_ca in certificate_authority table and for_external_ca in certificate_generation_info table on pkicoredb database in version 2.5.0"
                ;&
        "2.5.0") echo "Upgraded to version 2.6.0"
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/update.tables_2.6.0.ddl
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.defaultdata_2.6.0.ddl
                applySchemaUsingRole $DB $DB_GROUP $MIGRATION_PATH/data_migration_2.5.0_to_2.6.0.ddl
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.6.0.ddl
                checkExitCode "Added new columns subject_unique_identifier_value in caentity table and issuer_signature_algorithm,issuer_unique_identifier_value,subject_unique_identifier_value in certificate_generation_info table on pkicoredb database in version 2.6.0"
                ;&
        "2.6.0") echo "Upgraded to version 2.7.0"
                conn_limit=$(readDBConnectionLimit $DB)
                applySchema $DB $DDLS_PATH/kill.ongoing.trans.ddl
                stopAcceptingNewDBConnectionRequests $DB
                waitForCompletionOfOngoingTransactions 5
                killOngoingTransOnTable $DB entity_info
                createIndex $DB idx_core_entity_info entity_info status_id,issuer_id,name
                killOngoingTransOnTable $DB crlinfo
                createIndex $DB idx_core_crlinfo crlinfo crl_number,crl_id,certificate_id
                resumeAcceptingNewDBConnections $DB $conn_limit
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.7.0.ddl
                checkExitCode "Added Index for the tables crlInfo,entity_info in pkicoredb in version 2.7.0"
                ;&
        "2.7.0") echo "Upgraded to version 2.8.0"
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.8.0.ddl
                checkExitCode "Role based password authentication when making a connection in pkicoredb database for version 2.8.0"
                ;&
        "2.8.0") echo "Upgraded to version 2.9.0"
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.9.0.ddl
                checkExitCode "Role based password authentication in pkicoredb database for version 2.9.0"
                ;&
        "2.9.0") echo "Upgraded to version 2.10.0"
                applySchema $DB $MIGRATION_PATH/data_migration_2.9.0_to_2.10.0.ddl
                applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.10.0.ddl
                checkExitCode "Replace "CN=COMUser" with "CN=userName" in subject_alt_name column of entity_info table in pkicoredb in version 2.10.0"
                ;&
        "2.10.0") echo "Upgraded to version 2.11.0"
                  applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/update.tables_2.7.0.ddl
                  applySchemaUsingRole $DB $DB_GROUP $DDLS_PATH/insert.dbversion_2.11.0.ddl
                  checkExitCode "Alter the validity column of certificate_generation_info table to 15 in pkicoredb in version 2.11.0"
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

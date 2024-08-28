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

source /ericsson/pki_postgres/db/pkicore/lib/postgres01.config
source /ericsson/pki_postgres/db/pkicore/config/pkicoredb.config
source /ericsson/enm/pg_utils/lib/pg_password_library.sh

#*****************************************************************************#
#This function creates a log file in the specified location, if the required
#log file doesn't exists. Otherwise updates the existing log file with info
#and error details.
#*****************************************************************************#
function logRotate() {
    if [ -f ${INSTALL_LOG_DIR}/${LOG_FILE} ]; then
        local LDATE=`date +[%m%d%Y%T]`
        mv ${INSTALL_LOG_DIR}/${LOG_FILE} ${INSTALL_LOG_DIR}/${LOG_FILE}.${LDATE}
        touch ${INSTALL_LOG_DIR}/${LOG_FILE}
        chmod a+w ${INSTALL_LOG_DIR}/${LOG_FILE}
    else
        if [ ! -d "${INSTALL_LOG_DIR}" ]; then
            mkdir -p ${INSTALL_LOG_DIR}
        fi
        touch ${INSTALL_LOG_DIR}/${LOG_FILE}
        chmod a+w ${INSTALL_LOG_DIR}/${LOG_FILE}
    fi
}

#*****************************************************************************#
# This function logs the execution status of a particular process or a command
# $1 refers to the comments passed as argument to checkExitCode function
#*****************************************************************************#
function checkExitCode(){
    if [ $? -eq 0 ];  then
        infoLog "Step: $1 finished successfully"
        return 0;
    fi
    infoLog "Step: $1 failed. Exiting..."
    exit 1
}

#*****************************************************************************#
# This function applies a particular schema to Database
# $1 refers to database name
# $2 refers to ddl file
#*****************************************************************************#
function applySchema() {
    database=$1
    DDL_FILE=$2

    infoLog "Applying schema ${DDL_FILE} to ${database} "

    if [ -f ${DDL_FILE} ]; then
        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d${database} -q -w -f ${DDL_FILE} 2>>${INSTALL_LOG_DIR}/${LOG_FILE}
        checkExitCode "applying Schema ${DDL_FILE} to ${database} "
    else
        infoLog " ${DDL_FILE} is missing!"
        exit 1
    fi
}

#*****************************************************************************#
# This function applies a particular schema to Database using a particular role
# $1 refers to database name
# $2 refers to role name
# $3 refers to ddl file
#*****************************************************************************#
function applySchemaUsingRole() {
    database=$1
    role=$2
    DDL_FILE=$3
    infoLog "Applying schema to ${database} using user ${role}"

    if [ -f ${DDL_FILE} ]; then
        PGPASSWORD=ericsson ${PG_ROOT}/psql -U${role} -h${HOSTNAME} -d${database} -q -w -f ${DDL_FILE} 2>>${INSTALL_LOG_DIR}/${LOG_FILE}
        checkExitCode "applying Schema ${DDL_FILE} to ${database} using user ${role}"
    else
        infoLog " ${DDL_FILE} is missing!"
        exit 1
    fi
}

#*****************************************************************************#
# This function checks whether required role exists on DB node and creates the
# role if required and applies the role to a particular database
# This role (user) will create db and tables
# $1 refers to database name
# $2 refers to role name
#*****************************************************************************#
function createRole(){
    database=$1
    role=$2

    isRoleExists ${role}
    is_role_exists=$?

    infoLog "Creating role ${role} and applying role to database ${database}"

    if [ ${is_role_exists} -gt 0 ]; then
        infoLog "${role} Role already exists no further action required"
    else
        infoLog "Creating ${role} Role"
        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
        CREATE ROLE ${role} WITH LOGIN ENCRYPTED PASSWORD 'ericsson' SUPERUSER CREATEDB CREATEROLE REPLICATION VALID UNTIL 'infinity';
EOF

        infoLog "Applying ${role} Role"
        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
        ALTER DATABASE ${database} OWNER TO ${role};
EOF
    fi
    checkExitCode "Creating role ${role} if role doesn't exists on DB node and applying role to database ${database}"
}

#*****************************************************************************#
# This method creates a group with is specific to particular database and adds
# required roles to group
# $1 refers to database name
# $2 refers to group name
# $3 refers to role name
#-----------------------------------------------------------------------------#
function createGroupAndAddRoleToGroup(){
    database=$1
    grpname=$2
    dbrole=$3

    isRoleExists ${grpname}
    is_role_exists=$?

    infoLog "Creating group ${grpname} to include ${dbrole} role"

    if [ ${is_role_exists} -gt 0 ]; then
        infoLog "${grpname} group already exists no further action required"
    else
        infoLog "Creating group ${grpname}"
        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d${database} <<EOF 2>/dev/null
        CREATE GROUP ${grpname} WITH LOGIN ENCRYPTED PASSWORD 'ericsson' NOSUPERUSER NOCREATEDB NOCREATEROLE REPLICATION VALID UNTIL 'infinity';
EOF
    fi
    checkExitCode "Creating group ${grpname} if group doesn't exists on DB node "

    infoLog "Adding ${dbrole} role to ${grpname} group"

    PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d${database} <<EOF 2>/dev/null
    GRANT ${grpname} TO ${dbrole};
EOF
    checkExitCode "Adding role ${dbrole} to group ${grpname}"

}

#*****************************************************************************#
# This method checks for existence of a particular table in the given database
# $1 refers to database name
# $2 refers to table name
#*****************************************************************************#
function isTableExists(){
    database=$1
    table=$2
    DB_TABLE_TEST=${TMP_DIR}/${database}_${table}_table_test
    local LDATE=`date +[%Y-%m-%dT%H:%M:%S:%N]`
    infoLog "Checking for ${table} table in ${database}"
    if ls ${DB_TABLE_TEST}* 1>/dev/null 2>&1; then
        find ${DB_TABLE_TEST}* -mtime +7 -exec rm -rf {} \;
    fi

    PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d${database} <<EOF 1>${DB_TABLE_TEST}.${LDATE} 2>/dev/null
    SELECT * FROM pg_tables WHERE tablename='${table}';
EOF
    checkExitCode "Verifying whether ${table} exists in ${database} "
    is_db_table=`grep -i ${table} ${DB_TABLE_TEST}.${LDATE} | wc -l`
    return $is_db_table
}


#*****************************************************************************#
# This method checks for existence of a particular role in the given database
# $1 refers to role name
#*****************************************************************************#
function isRoleExists(){
    role=$1
    DB_ROLE_TEST=${TMP_DIR}/${role}_role_test
    infoLog "Checking for ${role} role"
    local LDATE=`date +[%Y-%m-%dT%H:%M:%S:%N]`
    if ls ${DB_ROLE_TEST}* 1>/dev/null 2>&1; then
        find ${DB_ROLE_TEST}* -mtime +7 -exec rm -rf {} \;
    fi

    PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 1>${DB_ROLE_TEST}.${LDATE} 2>/dev/null
    SELECT * FROM pg_roles WHERE rolname = '${role}';
EOF
    checkExitCode "Checking whether ${role} exists in pg_roles"
    is_role_exists=`grep -i ${role} ${DB_ROLE_TEST}.${LDATE} | wc -l`
    return $is_role_exists
}


#*****************************************************************************#
# This method alters the given role with no super user permissions
# $1 refers to role name
#*****************************************************************************#
function revokeSuperUserPermissions(){
    role=$1

    isRoleExists ${role}
    is_role_exists=$?

    infoLog "Revoking ${role} role super user permissions"

    if [ ${is_role_exists} -gt 0 ]; then

         infoLog "Revoking the super user permissions from the ${role} role"
         PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
         ALTER ROLE ${role} WITH ENCRYPTED PASSWORD 'ericsson' NOSUPERUSER NOCREATEDB NOCREATEROLE;
EOF
    fi
    checkExitCode "Revoking ${role} role super user permissions"

}

#*****************************************************************************#
# This method revokes connection permissions on database from public and will
# give permissions to privileged users
# $1 refers to database name
# $2 refers to role name
#*****************************************************************************#
function revokeDbPermissions() {
    database=$1
    role=$2

    infoLog "Revoking connection on database ${database} from public"

    PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
    REVOKE CONNECT ON DATABASE ${database} FROM PUBLIC;
EOF
    checkExitCode "Revoking connection on database ${database} from public"


    infoLog "Granting connection on database ${database} to ${role} role"
    PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
    GRANT CONNECT ON DATABASE ${database} to ${role};
EOF
    checkExitCode "Granting connection on database ${database} to ${role} role"

}

#*****************************************************************************#
# This method fetches the postgres password from encrypted file. This password
# is used to connect to postgresql using postgres user.
#*****************************************************************************#
function fetchPostgresPassword() {
    infoLog "Fetching pg_password from encrypted file"
    if [ -f ${FILE_DIR}/${FILE} ]; then
        touch ${FILE_DIR}/${FILE}
        chmod a+w ${FILE_DIR}/${FILE}
    else
        if [ ! -d "${FILE_DIR}" ]; then
            mkdir -p ${FILE_DIR}
        fi
        touch ${FILE_DIR}/${FILE}
        chmod 600 ${FILE_DIR}/${FILE}
    fi
    export_password
    echo "${PGPASSWORD}" >${FILE_DIR}/${FILE}
    checkExitCode "Fetching pg_password from encrypted file"
}

#*****************************************************************************#
# This method unsets the postgres password from PGPASSWORD variable and removes
# the hidden file which contains password.
#*****************************************************************************#
function unsetPassword() {
    infoLog "Removing hidden password file"

    rm -rf ${FILE_DIR}/${FILE}

    checkExitCode "Removing hidden password file"
}

#*****************************************************************************#
# This method creates the index for the given table on the given list of columns
# $1 refers to database name
# $2 refers to Index Name
# $3 refers to Table Name
# $4 refers to Columns on which Indexing should be applied
#*****************************************************************************#
function createIndex() {
    database=$1
    index_name=$2
    table_name=$3
    columns=$4
    isIndexExists=`PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d ${database} -Atc "SELECT COUNT(*) FROM PG_CLASS WHERE RELNAME = '${index_name}'"`;
    if [ ${isIndexExists} -eq 0 ]; then
        infoLog "Creating index on ${columns} for the table ${table_name}"
        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d ${database} <<EOF 2>/dev/null
        CREATE INDEX ${index_name} ON ${table_name} (${columns});
EOF
    else
        infoLog "Index ${index_name} already exists"
    fi
}

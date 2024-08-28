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
# Pre-requisite : Role kaps is already created
###########################################################################

source /ericsson/pki_postgres/db/kaps/config/kapsdb.config
source /ericsson/pki_postgres/db/kaps/lib/db-shared-library.sh
source /ericsson/pki_postgres/db/kaps/lib/postgres01.config

#*****************************************************************************#
# This function drops the <kaps> role if role exists in pg_roles
#*****************************************************************************#
function drop_role(){
    role=$1
    isRoleExists ${role}
    is_role_kaps=$?

    if [ ${is_role_kaps} -gt 0 ]; then

         infoLog "Revoking the super user permissions from the ${role} role"
         PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
         ALTER ROLE ${role} WITH NOSUPERUSER NOCREATEDB NOCREATEROLE;
EOF
         checkExitCode "Revoking ${role} role super user permissions"

         infoLog "Altering permissions on ${DB} database to postgres user"
         PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
         ALTER DATABASE ${DB} OWNER TO ${PG_USER};
EOF
         checkExitCode "Altering permissions on ${DB} database to postgres user"

         infoLog "Revoking ${role} role owner permissions from ${DB} database"
         PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
         REVOKE ALL ON DATABASE ${DB} FROM ${role};
EOF
         checkExitCode "Revoking ${role} role owner permissions from ${DB} database"

         infoLog "Dropping ${role} role"
         PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
         DROP ROLE ${role};
EOF
    else
         infoLog "${role} role does not exists"
    fi
    checkExitCode "Dropping role ${role}, if role exists in pg_roles"
}

##MAIN
fetchPostgresPassword
drop_role $DB_ROLE
drop_role $DB_INTERNAL_ROLE
unsetPassword


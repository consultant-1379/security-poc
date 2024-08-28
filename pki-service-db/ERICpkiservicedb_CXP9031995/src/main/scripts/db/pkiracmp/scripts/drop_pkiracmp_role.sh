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
# Pre-requisite : Role pkiracmp is already created
###########################################################################

source /ericsson/pki_postgres/db/pkiracmp/config/pkiracmpdb.config
source /ericsson/pki_postgres/db/pkiracmp/lib/db-shared-library.sh
source /ericsson/pki_postgres/db/pkiracmp/lib/postgres01.config

#*****************************************************************************#
# This function drops the <pkiracmp> role if role exists in pg_roles
#*****************************************************************************#
function drop_role(){
    isRoleExists ${DB_ROLE}
    is_role_pkiracmp=$?

    if [ ${is_role_pkiracmp} -gt 0 ]; then

         infoLog "Revoking the super user permissions from the ${DB_ROLE} role"
         PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
         ALTER ROLE ${DB_ROLE} WITH NOSUPERUSER NOCREATEDB NOCREATEROLE;
EOF
         checkExitCode "Revoking ${DB_ROLE} role super user permissions"

         infoLog "Altering permissions on ${DB} database to postgres user"
         PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
         ALTER DATABASE ${DB} OWNER TO ${PG_USER};
EOF
         checkExitCode "Altering permissions on ${DB} database to postgres user"

         infoLog "Revoking ${DB_ROLE} role owner permissions from ${DB} database"
         PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
         REVOKE ALL ON DATABASE ${DB} FROM ${DB_ROLE};
EOF
         checkExitCode "Revoking ${DB_ROLE} role owner permissions from ${DB} database"

         infoLog "Dropping ${DB_ROLE} role"
         PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
         DROP ROLE ${DB_ROLE};
EOF
    else
         infoLog "${DB_ROLE} role does not exists"
    fi
    checkExitCode "Dropping role ${DB_ROLE}, if role exists in pg_roles"
}

##MAIN
fetchPostgresPassword
drop_role
unsetPassword

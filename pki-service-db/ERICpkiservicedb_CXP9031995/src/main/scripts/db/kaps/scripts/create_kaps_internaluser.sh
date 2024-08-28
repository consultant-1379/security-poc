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

source /ericsson/pki_postgres/db/kaps/lib/postgres01.config
source /ericsson/pki_postgres/db/kaps/config/kapsdb.config

#*****************************************************************************
# This function checks whether required kapsinternaluser role exists on DB node
# and creates the role if required
#*****************************************************************************
function createkapsInternalRole(){

    isRoleExists ${DB_INTERNAL_ROLE}
    is_role_exists=$?

    if [ ${is_role_exists} -gt 0 ]; then
        infoLog "${DB_INTERNAL_ROLE} Role already exists no further action required"
    else
        infoLog "Creating ${DB_INTERNAL_ROLE} Role"
        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} <<EOF 2>/dev/null
        CREATE ROLE ${DB_INTERNAL_ROLE} WITH LOGIN ENCRYPTED PASSWORD 'ericsson' NOSUPERUSER NOCREATEDB NOCREATEROLE REPLICATION VALID UNTIL 'infinity';
EOF
    fi

    checkExitCode "Creating role $DB_INTERNAL_ROLE if role doesn't exists on DB node"
}


#***************************************************************************
# alterSymmetricKeyTableOwner ()
# alter the table symmetric_key owner to new role <kapsgrp>
#***************************************************************************
function alterSymmetricKeyTableOwner(){

   infoLog "Checking for symmetric_key table.."

   isTableExists $DB $SYMMETRIC_KEY_TABLE
   is_symmetric_key_table=$?

   infoLog "Changing the table symmetric_key and sequence seq_symmetric_key_id owner to  kapsgrp role"

   if [ $is_symmetric_key_table -gt 0 ]; then

       PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d $DB <<EOF 2>/dev/null
       ALTER TABLE $SYMMETRIC_KEY_TABLE OWNER TO $DB_GROUP;
EOF
       checkExitCode "Changing the table symmetric_key owner to  kapsgrp role "

       PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d $DB <<EOF 2>/dev/null
       GRANT ALL ON $SYMMETRIC_KEY_TABLE TO $DB_GROUP;
EOF
       checkExitCode "Granting permission on table symmetric_key to kapsgrp role"

       PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME}  -d $DB <<EOF 2>/dev/null
       ALTER SEQUENCE $SEQ_SYMMETRIC_KEY_ID OWNER TO $DB_GROUP;
EOF
       checkExitCode "Changing the sequence seq_symmetric_key_id owner to  kapsgrp role "

       PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME} -d $DB <<EOF 2>/dev/null
       GRANT ALL ON $SEQ_SYMMETRIC_KEY_ID TO $DB_GROUP;
EOF
       checkExitCode "Granting all on sequence seq_symmetric_key_id to kapsgrp role "

   else
       infoLog "symmetric_key table doesn't exists in kapsdb database"

   fi
   checkExitCode "Changing the table symmetric_key and sequence seq_symmetric_key_id owner to  kapsgrp role "

}


#**********************************************************************************************
# revokeOldUserAccess ()
# revoke the old user <kaps> access from symmetric_key table and seq_symmetric_key_id sequence
#**********************************************************************************************
function revokeOldUserAccess(){
    infoLog "Checking for symmetric_key table.."

    isTableExists $DB $SYMMETRIC_KEY_TABLE

    is_symmetric_key_table=$?

    infoLog "Revoking the kaps user rights from the symmetric_key table and seq_symmetric_key_id sequence "

    if [ $is_symmetric_key_table -gt 0 ]; then

        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME}  -d$DB <<EOF 2>/dev/null
        REVOKE ALL ON $SYMMETRIC_KEY_TABLE FROM $DB_ROLE,GROUP PUBLIC;
EOF
        checkExitCode "Revoking the kaps user rights from  symmetric_key table "

        PGPASSWORD=$(cat ${FILE_DIR}/${FILE}) ${PG_ROOT}/psql -U${PG_USER} -h${HOSTNAME}  -d$DB <<EOF 2>/dev/null
        REVOKE ALL ON $SEQ_SYMMETRIC_KEY_ID FROM $DB_ROLE,GROUP PUBLIC;
EOF
        checkExitCode "Revoking the kaps user rights from  seq_symmetric_key_id sequence "

    else
        infoLog "symmetric_key table doesn't exists in kapsdb database"

    fi
    checkExitCode "Revoking the kaps user rights from the symmetric_key table and seq_symmetric_key_id sequence "

}

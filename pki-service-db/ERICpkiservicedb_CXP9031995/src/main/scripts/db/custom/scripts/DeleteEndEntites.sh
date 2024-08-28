#!/usr/bin/env bash


#########################################################
# This script is used to Delete the End entites which are in the DELETED state.
# Author: xpradks
#########################################################

_PSQL="/opt/rh/postgresql/bin/psql"
_RM="/bin/rm"
_CHMOD="/bin/chmod"
_SED="/bin/sed"
_CAT="/bin/cat"
DELETED_STATUS="5";

#########################################################
# These functions logs a message to /var/log/messages
# Arguments:
#       $1 - Message
# Return: 0
#########################################################
error()
{
  logger  -t "${LOG_TAG}" -p user.err "ERROR ( ${SCRIPT_NAME} ): $1"
  printf "\n $1 \n\n"
}

info()
{
  logger  -t "${LOG_TAG}" -p user.notice "INFORMATION ( ${SCRIPT_NAME} ): $1"
  printf "\n $1 \n\n"
}

usage() {
printf "\nUsage: $0
\n
\n [ -l  | --list Lists all EndEntites whose status is in "DELETED" State]
\n [ -all Deletes all EndEntites whose status is in "DELETED" State]
\n [ -el | --entitylist <EE1(,EE2,EE3)> Deletes the given EndEntites(single or multiple), if they are in "DELETED" State]
\n [ -ef | --entityfile <file path> Deletes the EndEntites given in the file, if they are in "DELETED" State]
\n [ -h  | --help Display the help content]
\n Note: Entity full names must be provided as inputs to -el or -ef(in the file). Expression or short names of entites are not allowed.
\n       For the option of Entity File, the file must contain only one entity in each line. \n\n" 1>&2; exit 1;
}

#########################################################
# This function prepares a plsql function to delete
# the Entities on PKI-Managerdb.
#########################################################
prepareManagerdbSqlFile(){
managerdb_sql_file="/tmp/$$_ManagerDbFunction.sql"
"$_RM" -rf "$managerdb_sql_file"
(
"$_CAT" <<'END_MANAGER_DB_SCRIPT'
CREATE OR replace FUNCTION delete_end_entitydata(entity_name CHARACTER varying) returns void AS $$
DECLARE

  endentity_id       bigint;
  e_cert_req_id      INTEGER;
  c_id_arr           bigint[];
  cert_id            INTEGER;
  cert_req_id        bigint[];

BEGIN

  SELECT id
  INTO   endentity_id
  FROM   entity
  WHERE  name=entity_name;

      SELECT ARRAY
           (
                  SELECT certificate_id
                  FROM   entity_certificate
                  WHERE  entity_id=endentity_id)
    INTO   c_id_arr;

      SELECT ARRAY
           (
                  SELECT certificate_request_id
                  FROM certificate_generation_info
                  WHERE  entity_info=endentity_id)
    INTO   cert_req_id;

  DELETE
  FROM   revocation_request_certificate
  WHERE  certificate_id=ANY (c_id_arr);

  DELETE
  FROM   revocation_request
  WHERE  entity_id=endentity_id;

  DELETE
  FROM   certificate_generation_info
  WHERE  certificate_generation_info.entity_info=endentity_id;

  DELETE
  FROM   certificate_request
  WHERE  id=ANY (cert_req_id);

  DELETE
  FROM   entity_certificate
  WHERE  certificate_id=ANY (c_id_arr);

  DELETE
  FROM   certificate
  WHERE  id=ANY (c_id_arr);

  DELETE
  FROM   entity_cert_exp_notification_details
  WHERE  entity_id=endentity_id;

  DELETE
  FROM   subject_identification_details
  WHERE  entity_id=endentity_id;

  DELETE
  FROM   entity
  WHERE  id=endentity_id;

END $$ LANGUAGE plpgsql volatile cost 100;
END_MANAGER_DB_SCRIPT
) > "$managerdb_sql_file"
"$_CHMOD" 777 "$managerdb_sql_file"
"$_PSQL" -q -t -U postgres -d pkimanagerdb -f "$managerdb_sql_file" 1>&2;
}

#########################################################
# This function prepares a plsql function to delete
# the Entities on PKI-Coredb.
#########################################################
prepareCoredbSqlFile(){
coredb_sql_file="/tmp/$$_CoreDbFunction.sql"
"$_RM" -rf "$coredb_sql_file"
(
"$_CAT" <<'END_CORE_DB_SCRIPT'
CREATE OR replace FUNCTION delete_end_entitydata(entity_name CHARACTER varying) returns void AS $$
  DECLARE

    e_id               bigint;
    c_id_arr           bigint[];
    cert_req_id        bigint[];
  BEGIN

    SELECT id
    INTO   e_id
    FROM   entity_info
    WHERE  name=entity_name;

    SELECT ARRAY
           (
                  SELECT certificate_id
                  FROM   entity_certificate
                  WHERE  entity_id=e_id)
    INTO   c_id_arr;

    SELECT ARRAY
           (
                  SELECT certificate_request_id
                  FROM certificate_generation_info
                  WHERE  entity_info=e_id)
    INTO   cert_req_id;

    DELETE
    FROM   revocation_request_certificate
    WHERE  certificate_id=ANY (c_id_arr);

    DELETE
    FROM   revocation_request
    WHERE  entity_id=e_id;

    DELETE
    FROM   certificate_generation_info
    WHERE  entity_info=e_id;

    DELETE
    FROM   certificate_request
    WHERE  id=ANY (cert_req_id);

    DELETE
    FROM   entity_certificate
    WHERE  entity_id=e_id;

    DELETE
    FROM   certificate
    WHERE  id=ANY (c_id_arr);

    DELETE
    FROM   entity_info
    WHERE  id=e_id;

  END;
  $$ LANGUAGE plpgsql volatile cost 100;
END_CORE_DB_SCRIPT
) > "$coredb_sql_file"
"$_CHMOD" 777 "$coredb_sql_file"
"$_PSQL" -q -t -U postgres -d pkicoredb -f "$coredb_sql_file" 1>&2;
}

#########################################################
# This function gets the deleted entity list from the db.
#########################################################
getDeletedEntityList(){
DELETED_ENTITY_LIST="/tmp/$$_EntityList.txt";
"$_RM" -rf "$DELETED_ENTITY_LIST"
"$_PSQL" -t -U postgres -d pkimanagerdb -c "SELECT name from entity where status_id=${DELETED_STATUS}"| uniq |sort > "$DELETED_ENTITY_LIST"
"$_SED" -i "s/ //g;/^$/d" "$DELETED_ENTITY_LIST"
}

#########################################################
# This function checks the entity is deleted properly or not.
#########################################################
checkEntityExists(){
CHECK_ENTITY_LIST="/tmp/$$_Deleted_EntityList.txt";
"$_RM" -rf "$CHECK_ENTITY_LIST"
"$_PSQL" -t -U postgres -d pkimanagerdb -c "SELECT name from entity where status_id=${DELETED_STATUS} AND name='${1}'"| uniq |sort > "$CHECK_ENTITY_LIST"
"$_SED" -i "s/ //g;/^$/d" "$CHECK_ENTITY_LIST"
}

#########################################################
# This function gets the deleted entity list from db and
# will exit if the list is empty.
#########################################################
prepareDeletedEntityListFromDB(){
getDeletedEntityList
if [[ ! -s "$DELETED_ENTITY_LIST" ]];then
  error "\n There is no End entity which is in DELETED state \n"
  exit 1;
fi
}

#########################################################
# This function prepares an array of entities for the given EL input.
#########################################################
getEntityNamesFromELInput(){
local inputEL="$EL"
    if [[ "$inputEL" = *","* ]];then
      IFS=',' read -r -a entityListArray <<< "$inputEL"
    else
      entityListArray=("${inputEL[@]}")
    fi

}

#########################################################
# This function prepares an array of entities for the inputs given in the EF file.
#########################################################
getEntityNamesFromEFInput(){
if [[ ! -f "$1" ]];then
error "\n The given file does not exists \n"
exit 1;
elif [[ ! -s "$1" ]];then
error "\n The given file is an empty file \n"
exit 1;
fi

mapfile -t entityListArray < "$1"
}

#########################################################
# This function prepares an array of verified entities
# from the user inputs over the enitity list obtained from DB.
#########################################################
prepareEntityList(){
for i in "${entityListArray[@]}"
  do
   i=`echo "${i}" | sed -e "s/^[ \t]*//;s/[ \t]*$//"`
   if [[ "$i" == "" ]];then
    continue;
   elif [[ "$i" == *"*"* ]];then
    info "Given input [ \"$i\" ] is an Expression for Entity. Expression cannot be given as input";
    continue;
   fi

   tempArray=(`${_CAT} $DELETED_ENTITY_LIST|grep -e "^${i}$" -ie  "^${i}-oam$" -ie  "^${i}-ipsec$"`);
   if [[ "$tempArray" == "" ]];then
    info "Given Entity [ \"$i\" ] is not found in the DELETED state or does not Exists ";
    continue;
   fi
 verifiedEntityNamesArray+=(${tempArray[@]});
done
}

#########################################################
# This function prepares a final array of verified entities
# from the user inputs.
#########################################################
prepareEntityArrayFromInput(){

if [[ "$EL" != "" ]];then
 getEntityNamesFromELInput
 prepareEntityList
elif [[ "$EF" != "" ]];then
 getEntityNamesFromEFInput "$EF"
 prepareEntityList
elif [[ "$ALL" == "all" ]];then
 mapfile -t verifiedEntityNamesArray < "$DELETED_ENTITY_LIST"
else
 echo "Invalid Output"
 exit 1;
fi
verifiedEntityNamesArray=($(echo "${verifiedEntityNamesArray[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
}

#########################################################
# This function verifies the complete deletion of the given entity.
#########################################################
verifyEEDeletedStatus(){
local -r endEntity="$1"
checkEntityExists "${endEntity}"
"${_CAT}" "$CHECK_ENTITY_LIST"|grep "${endEntity}$"
if [[ "$?" == 0 ]];then
 error "Error occurred while deleting the entity : [ ${endEntity} ]"
 else
 info "The Entity : [ ${endEntity} ] is Deleted successfully"
 fi
}

#########################################################
# This function cleans up all the files and drop the functions inserted in the DB's
#########################################################
performCleanUpActivity(){
"$_RM" -rf "$managerdb_sql_file"
"$_RM" -rf "$coredb_sql_file"
"$_RM" -rf "$DELETED_ENTITY_LIST"

"$_PSQL"  -U postgres -d pkimanagerdb -c "DROP FUNCTION delete_end_entitydata(entity_name character varying)" >> /dev/null 2>&1;
"$_PSQL"  -U postgres -d pkicoredb -c "DROP FUNCTION delete_end_entitydata(entity_name CHARACTER varying)" >> /dev/null 2>&1;

}

#########################################################
# This function is used to ask password to the user
#########################################################
performPasswordRequest(){
printf "\n Enter the Psql password\n"
read -s passwd
export PGPASSWORD="${passwd}"
if [[ -e /gp/global.properties ]];
then
export PGHOST="postgres";
fi
"$_PSQL" -t -U postgres -d pkimanagerdb -c '\q' >> /dev/null 2>&1;
if [ "$?" != 0 ]; then
printf "\n The PSQL credential provided is invalid\n"
exit 1;
fi

}

######################
# Manage arguments   #
######################

if [[ "$#" -ge 0 ]];then

Arg="$1"

case "$Arg" in
    -l|--list)
    performPasswordRequest
    prepareDeletedEntityListFromDB
    printf "\n The Entities which are in DELETED state are as follows:\n"
    "$_CAT" "$DELETED_ENTITY_LIST"
    exit 0;

    ;;
    -all)
    ALL="all"

    ;;
    -el|--entitylist)
    EL="${@:2}"

    ;;
    -ef|--entityfile)
    EF="$2"

    ;;
    -h|--help)
    usage;

    ;;
    *)    # unknown option
    printf "\nInvalid argument is given, please check the usage below:\n"
    usage;

    ;;
esac
fi

######################
# Main script starts #
######################
performPasswordRequest
prepareManagerdbSqlFile
prepareCoredbSqlFile
prepareDeletedEntityListFromDB
prepareEntityArrayFromInput

if [[ "${verifiedEntityNamesArray[@]}" == "" ]];then
    performCleanUpActivity
    exit 1;
else
    for entity in "${verifiedEntityNamesArray[@]}"
    do

      if [[ "${entity}" != "" ]];then
      "$_PSQL"  -U postgres -d pkimanagerdb -c "select delete_end_entitydata('${entity}')" >> /dev/null 2>&1;

      "$_PSQL"  -U postgres -d pkicoredb -c "select delete_end_entitydata('${entity}')" >> /dev/null 2>&1;

      verifyEEDeletedStatus "${entity}"
      fi

    done
fi

#cleanup process
performCleanUpActivity
exit 0;

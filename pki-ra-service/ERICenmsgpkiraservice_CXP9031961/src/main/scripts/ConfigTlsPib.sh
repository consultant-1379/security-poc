#!/bin/bash

###########################################################################
# COPYRIGHT Ericsson 2020
#
# The copyright to the computer program(s) herein is the property of
# Ericsson Inc. The programs may be used and/or copied only with written
# permission from Ericsson Inc. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
###########################################################################

readonly TLS_VERSION_1_0="TLSv1.0";
readonly TLS_VERSION_1_1="TLSv1.1";
readonly TLS_VERSION_1_2="TLSv1.2";
readonly TLS_VERSION_ALL="TLSv1.0,TLSv1.1,TLSv1.2";
readonly TLS_ECIM_PIB="enabledTLSProtocolsECIM";
readonly TLS_CPP_PIB="enabledTLSProtocolsCPP";
readonly TLS_EXT_LDAP_PIB="enabledTLSProtocolsExtLDAP";
readonly GLOBAL_PROPERTIES_FILE="/ericsson/tor/data/global.properties"
readonly DDC_ON_CLOUD_KEY="DDC_ON_CLOUD="

readonly INVALID_PIB_NAME="invalid_pib_name";
readonly INVALID_PIB_VALUE="invalid_pib_Value";
readonly _PIB_CONFIG_SCRIPT="/opt/ericsson/PlatformIntegrationBridge/etc/config.py";
readonly LOG_TAG="CONFIG_TLS_PIB";
readonly SCRIPT_NAME="${0}";

_FORCE=false;


#########################################################
# These functions will log a message to /var/log/messages
# Arguments:
#       $1 - Message
# Return: 0
#########################################################
error()
{
   logger  -t ${LOG_TAG} -p user.err "ERROR: ( ${SCRIPT_NAME} ): $1"

}

info()
{
   logger  -t ${LOG_TAG} -p user.notice "INFORMATION: ( ${SCRIPT_NAME} ): $1"

}

warn()
{
   logger  -t ${LOG_TAG} -p user.warn "WARNING: ( ${SCRIPT_NAME} ): $1"

}

#########################################################
# These methods are used to provide the help content
#########################################################
USAGE()
{
  if [[ "$INVALID_PIB_NAME" == "$1" ]]; then
   USAGE_PIB_NAME "$2"
  elif [[ "$INVALID_PIB_VALUE" == "$1" ]]; then
   USAGE_PIB_VALUE "$2"
  else
   usg_tmp_file="/tmp/$$_1"
   rm -rf "$usg_tmp_file"
(
cat <<'END_USG'

Usage:

 /ericsson/pkira/data/scripts/ConfigTlsPib.sh [options]

 options:

 [-pn|--pibname] <PIB Parameter Name> [-pv|--pibvalue] <PIB Parameter Value> (-f|--force) | [-h|--help] | [-r|--readAll]

          -h|--help      : Shows the help message and exit.

          -r|--readAll   : Returns the respective values of the TLS PIB Parameters.

          -pn|--pibname  : Parameter to provide TLS PIB parameter name.

          -pv|--pibvalue : Parameter to provide TLS PIB parameter value.

          -f|--force     : Updates the given TLS PIB parameter name and its value without user's confirmation.


 Ex:
  /ericsson/pkira/data/scripts/ConfigTlsPib.sh -h

  /ericsson/pkira/data/scripts/ConfigTlsPib.sh --readAll

  /ericsson/pkira/data/scripts/ConfigTlsPib.sh -pn "enabledTLSProtocolsECIM" -pv "TLSv1.2,TLSv1.1"

  /ericsson/pkira/data/scripts/ConfigTlsPib.sh --pibname "enabledTLSProtocolsECIM" --pibvalue "TLSv1.2,TLSv1.1" --force 

Description:

This Script is used to verify and configure the TLS protocol versions to the following PIB Parameters:

END_USG
) > "$usg_tmp_file"
chmod 555 "$usg_tmp_file"
cat "$usg_tmp_file"
USAGE_PIB_NAME
USAGE_PIB_VALUE
rm -rf "$usg_tmp_file"
  fi
  exit 1
  }


 USAGE_PIB_NAME()
 {
 local name="$1"
 if [[ "$name" != "" ]]; then
         if [[ "$name" == "EMPTY" ]]; then
           state=empty; name="";
         else
           state=invalid;
         fi
 printf "\nThe given Pib name is $state : [$name]\n";
 error "The given Pib name is $state : [$name]";
 printf "\nFor supported Pib names, please check the help section using the argument -h| --help .\n\n"
 return
 fi
 printf "\nThe PIB parameter name shall be one among the below list \n\n"
 tmp2_file="/tmp/$$_2"
rm -rf "$tmp2_file"
(
cat <<'END_MAIN'
==========================
PIB Parameter Names
==========================
enabledTLSProtocolsCPP
enabledTLSProtocolsECIM
enabledTLSProtocolsExtLDAP
==========================
END_MAIN
) > "$tmp2_file"
chmod 555 "$tmp2_file"
cat "$tmp2_file";
rm -rf "$tmp2_file"
 }

 USAGE_PIB_VALUE()
 {
 local value="$1"
 if [[ "$value" != "" ]]; then
         if [[ "$value" == "EMPTY" ]]; then
           state=empty; value="";
         else
           state=invalid;
         fi
 printf "\nThe given Pib value is $state : [$value]\n";
 error "The given Pib value is $state : [$value]";
 printf "\nFor supported Pib values information , please check the help section using the argument -h| --help .\n\n"
 return
 fi
 printf "\nThe supported PIB parameter values shall be either one or combination of the below TLS version Protocol list.\n\n";

 tmp3_file="/tmp/$$_3"
rm -rf "$tmp3_file"
(
cat <<'END_MA'
==============================
Supported PIB Parameter Values
==============================
          TLSv1.0
-
          TLSv1.1
-
          TLSv1.2
==============================
END_MA
) > "$tmp3_file"
chmod 555 "$tmp3_file"
column -t -s "-" "$tmp3_file";
printf "\nNote: In case of multiple TLS protocol value combinations to be provided,\nthe values need to be seperated by comma(,) and to be given in quotes(\"\").\n";
printf "\nSome of the possible combination examples of pib values are as follows:\n";
printf "\nEx: TLSv1.2 , \"TLSv1.1,TLSv1.2\" , \"TLSv1.0,TLSv1.1,TLSv1.2\" , \"TLSv1.2,TLSv1.0,TLSv1.1\" etc...\n\n";
rm -rf "$tmp3_file"
 }


#########################################################
# This method is used to validate the PIB parameter name
# and assign the respective default PIB value.
#########################################################
_VALIDATE_PIB_NAMES(){

        local -r input="$1";
        info "Validating the PIB Parameter name: [$input]";
        case "$input" in

        "$TLS_ECIM_PIB"|"$TLS_EXT_LDAP_PIB"|"$TLS_CPP_PIB")
                info "The PIB Parameter name is valid: [$input]"  ;;
        *)
                USAGE "$INVALID_PIB_NAME" "$input";;
        esac
        info "The PIB Parameter name is successfully validated.";
}

#########################################################
# This method is used to validate the PIB parameter value
#########################################################
_VALIDATE_PIB_PARAM_VALUES() {
        local -r input="$1";
        info "Validating the given PIB Parameter Value: [$input]";
        result=();
        for i in $(echo $input | sed "s/,/ /g")
        do

        case "${i,,}" in

        "${TLS_VERSION_1_0,,}")
                result+=( "$TLS_VERSION_1_0" ) ;;
        "${TLS_VERSION_1_1,,}")
                result+=( "$TLS_VERSION_1_1" ) ;;
        "${TLS_VERSION_1_2,,}")
                 result+=( "$TLS_VERSION_1_2" ) ;;
                             *)
                 USAGE "$INVALID_PIB_VALUE" "$i";
                break ;;
        esac
        done
          if [[ "${result[@]}" != "" ]];then
                pib_Value="$(echo "${result[@]}" | tr ' ' '\n' |  awk '!a[$0]++'  | tr '\n' ','|sed "s/.$//")"
          else
                error "Error occurred while validating the PIB parameter value : [$input]";
                printf "Error occurred while validating the PIB parameter value : [$input] \nPlease check the /var/log/messages for more details.\n\n";
                exit 1;
          fi
          info "The PIB Parameter Value is successfully validated.";
}


#########################################################
# This method is used to configure the PIB parameter with
# the validated PIB parameter name and its respective Value.
#########################################################
_CONFIGURE_PIB_PARAMETER(){
        local -r pibName="$1"
        local -r pibValue="$2"
        if [[ "$_FORCE" == "false" ]];then
                while true; do
                read -p "Do you wish to Configure the PIB parameter: [$pib_Name] with the value:[$pibValue] (y/n)?" yn
                case $yn in
                        [Yy][Ee][Ss]|[Yy]) break;;
                        [Nn][Oo]|[Nn] ) printf "\n\t\t\tConfiguration of PIB parameter has been interrupted !!!\n\n"; exit;;
                        * ) echo "Please answer yes or no.";;
                esac
                done
        fi
        info "Configuring the PIB Parameter: [$pibName] with the value: [$pibValue]"

        read_value=$("$_PIB_CONFIG_SCRIPT" read --app_server_address "$sps_server_name":8080 --name="$pibName");

        if [[ "$pibValue" != "$read_value" ]]; then
          updated_value=$("$_PIB_CONFIG_SCRIPT" update --app_server_address "$sps_server_name":8080 --name="$pibName" --value="$pibValue");	 
        else
          info "The PIB parameter : [$pibName] is already configured with the value: [$pibValue]";
          printf "\nThe PIB parameter : [$pibName] is already configured with the value: [$pibValue]\n\n";
          exit 0;
        fi

        if [[ $pibValue != $updated_value ]]; then
         error "Error occurred as: [$updated_value], while Configuring the PIB parameter: [$pib_Name] with the value:[$pibValue]";
         printf "\n\nError occurred while Configuring the PIB parameter: [$pib_Name] with the value:[$pibValue]\n\nPlease check the /var/log/messages for more details.\n\n";
         exit 1;
        fi
}



#########################################################
# These methods is used to read the TLS PIB parameter and
# displays its respective pib value.
#########################################################
_READING_PIB_VALUE() {
local -r PIB_NAME="$1"
read_value=$("$_PIB_CONFIG_SCRIPT" read --app_server_address "$sps_server_name":8080 --name="$PIB_NAME")
                if [[ "${read_value,,}" != *"tlsv1."* ]]; then
                        error "Error occurred as [$read_value], while reading the PIB parameter : [$PIB_NAME]";
                        read_value="ERROR"
                fi
echo "$read_value";
}

_READ_ALL_PIB_PARAMETER(){

                read_cppvalue="$(_READING_PIB_VALUE "enabledTLSProtocolsCPP")";
                read_ecimvalue="$(_READING_PIB_VALUE "enabledTLSProtocolsECIM")";
                read_extldapvalue="$(_READING_PIB_VALUE "enabledTLSProtocolsExtLDAP")";

tmp4_file="/tmp/$$_4"
rm -rf "$tmp4_file"
(
cat <<'END_READ'

==========================-|-============================
PIB Parameter Name        -|-PIB Parameter Value
==========================-|-============================
enabledTLSProtocolsCPP    -|-[cppvalue]
enabledTLSProtocolsECIM   -|-[ecimvalue]
enabledTLSProtocolsExtLDAP-|-[extldapvalue]
==========================-|-============================


END_READ
) > "$tmp4_file"
chmod 555 "$tmp4_file"
sed -i "s/cppvalue/$read_cppvalue/g" "$tmp4_file"
sed -i "s/ecimvalue/$read_ecimvalue/g" "$tmp4_file"
sed -i "s/extldapvalue/$read_extldapvalue/g" "$tmp4_file"
column -t -s "-" "$tmp4_file";
if [[ "$read_cppvalue$read_ecimvalue$read_extldapvalue" == *"ERROR"* ]]; then
   printf "\n\nError occurred while reading one or more TLS PIB parameters values. Please check the /var/log/messages for more details.\n\n";
fi
rm -rf "$tmp4_file"
exit 0;
}

#########################################################
# This method is used to read the sps instance from physical or cloud
#########################################################
get_sps_instance() {
  if [ -f ${GLOBAL_PROPERTIES_FILE} ] ; then
    isCloud=$(grep -Po "(?<=^${DDC_ON_CLOUD_KEY}).*" ${GLOBAL_PROPERTIES_FILE});

    if [[ "${isCloud,,}" == "true" ]]; then
     sps_server_name="$(consul members | grep -i sps |awk '{print $2}'|cut -d: -f1 |head -n 1)";
    else
     sps_server_name="$(cat /etc/hosts |grep -i sps |awk '{print $2}'|head -n 1)";
    fi
    info "The sps instance obatained is: [$sps_server_name]"
  else
    error "The ${GLOBAL_PROPERTIES_FILE} file doesnt exist"
    exit 1;
  fi
}

#########################################################
# The Main logic starts form here
#########################################################

if [[ "$@" == "" ]]; then
printf "\n Parameters are required.\n Please check the help section using the argument -h| --help .\n\n";
exit 1;
fi

get_sps_instance
while true; do
    case "$1" in
        -h|-\?|--help)
            USAGE
            exit
            ;;
        -pn|--pibname)
            if [[ "$2" ]]; then
                        if [[ "$pib_Name" != "" ]]; then  USAGE; fi;
                pib_Name="$2"
                shift
            fi
            ;;
        -pv|--pibvalue)
            if [ "$2" ]; then
                         if [[ "$pib_Value" != "" ]]; then  USAGE; fi;
                pib_Value="$2"
                shift
            fi
            ;;
           -f|--force)
                        _FORCE=true;
                        shift
                        ;;
            -r|--readAll)
                        _READ_ALL_PIB_PARAMETER;
                        shift
                        ;;
        --)
            shift
            break
            ;;
        -?*)
            printf 'Error: Unknown option : %s\n\n' $1 >&2
                        USAGE
            ;;
        *)  if [[ "$1" != "" ]]; then
            USAGE
                        fi
                        break

           ;;
    esac

    shift
done

if [[ "$pib_Name" == "" ]];then
USAGE "$INVALID_PIB_NAME" "EMPTY";
elif [[ "$pib_Value" == "" ]];then
USAGE "$INVALID_PIB_VALUE" "EMPTY";
fi

_VALIDATE_PIB_NAMES "$pib_Name";
_VALIDATE_PIB_PARAM_VALUES "$pib_Value";

echo -e "\n\n"

_CONFIGURE_PIB_PARAMETER "$pib_Name" "$pib_Value";

info "Successfully Configured the PIB parameter: [$pib_Name] with the value:[$pib_Value]";
printf "\n\nSuccessfully Configured the PIB parameter: [$pib_Name] with the value:[$pib_Value]\n\n";

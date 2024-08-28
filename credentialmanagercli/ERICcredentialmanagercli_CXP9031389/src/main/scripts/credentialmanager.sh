#!/bin/bash
#===============================================================================
#
#          FILE: credentialmanager.sh
#
#         USAGE: credentialmanager -i --install or -c --check
#
#   DESCRIPTION: this script is taking care to verify if java cli can run or not
#                according to the current status of SPS
#
#===============================================================================

set +o nounset                              # Treat unset variables without error

CLI_INSTALL_PATH=/opt/ericsson/ERICcredentialmanagercli


CLI_CONF_DIR=$CLI_INSTALL_PATH/conf
CLI_BIN_DIR=$CLI_INSTALL_PATH/bin

CLI_CONF_FILES=$CLI_CONF_DIR/credentialmanagerconf.sh

# allow memory check to run

memory_checker=false

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  cred_cli_log
#   DESCRIPTION:  write logs info on file is possible (according to level)
#    PARAMETERS:  $1 function_name, $2 (level) , $3 msg
#       RETURNS:  none
#-------------------------------------------------------------------------------

cred_cli_log (){

    local level=$1
    local msg=$2

    if [ "$level" -ge "${DEFAULT_LOG_LEVEL}" ] ; then
        echo -e "$(date +[%D-%T]) ${LOG_LEVEL_INFO_STRINGS[$level]} ${FUNCNAME[1]} \t $msg" &>> "$CRED_LOG_FILE"

	if [ "$level" == "$ERROR" ] ; then
	    userinfo="user.err"
	else
	    userinfo="user.notice"
	fi

        logger -t CREDENTIAL_MGR_CLI  -p $userinfo "${LOG_LEVEL_INFO_STRINGS[$level]} ${FUNCNAME[1]} $msg"
    fi
}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  find_second_part
#   DESCRIPTION:  find and return second part of the string passed after IFS char =
#    PARAMETERS:  $1
#       RETURNS:  what it founds after =
#-------------------------------------------------------------------------------

find_second_part() {

    local IFS="="
    input=$1
    set $input
    cred_cli_log "$DEBUG" "from  $input is $2"
    echo "$2"
}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  property_resolver
#   DESCRIPTION:  look for property passed as parameters
#    PARAMETERS:  property name ($2)  and filename  where to look ($1)
#       RETURNS:  property_name found or none in case of error
#-------------------------------------------------------------------------------

property_resolver() {

    cred_cli_log "$DEBUG" "parameters are: $1 $2 "

   output=$(grep "$2" "$1" )

    if [ -z "$output" ];  then
        cred_cli_log  "$ERROR"  "$2  not present in $1 file"
        return
    fi

    output_count=$(echo "$output" | wc -l)

    if [ "$output_count" -eq 1 ]; then
        name=$(find_second_part "$output")
        cred_cli_log "$INFO" "file=$1 pro=$2 found $name"
        echo "$name"
    else
       cred_cli_log "$ERROR" "find too many parameters outcount=$output_count out=$output"
       return
    fi

}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  check_ip_files
#   DESCRIPTION:  read $HOSTS_INFO_DIR  in order to find files with info about SPS SG
#                 ip address and related cred-m api version handled
#    PARAMETERS:  none
#       RETURNS:  files list
#-------------------------------------------------------------------------------

check_ip_files () {

    if [ ! -d "$HOSTS_INFO_DIR" ] ; then
        cred_cli_log "$ERROR" "folder $HOSTS_INFO_DIR not found"
        return;
    fi

    files=$(ls "$HOSTS_INFO_DIR" 2> /dev/null)

    if [ $? != 0 ];  then
        cred_cli_log  "$ERROR" "error on reading $HOSTS_INFO_DIR"
        return;
    fi

    cred_cli_log "$INFO" "sps files found are $files"
    echo  "$files";
}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  random_ind_creation
#   DESCRIPTION:  it creates a random list (from 0 to $1-1 parameters)
#    PARAMETERS:  $1 num of elements of random list $2 array where to save the list values
#       RETURNS:  none (arrays cannot be returned by shell functions)
#-------------------------------------------------------------------------------

random_ind_creation() {

    local -a local_random_array=$2
    local size=$(($1-1))

    cred_cli_log "$INFO" "size=$1"

    temp=$(shuf  -i 0-$size)
    eval $local_random_array="( ${temp[*]} )"

    cred_cli_log "$INFO" "rand_values are $temp"

}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  wrt_write_rest_info
#   DESCRIPTION:  it writes jboss config files used for rest interface
#    PARAMETERS:  $1 (parameters to be written)
#       RETURNS:  none
#-------------------------------------------------------------------------------

wrt_write_rest_info() {

    local rest_host_string=$1


    cred_cli_log "$INFO" "writing  $REST_CONFIGFILE_OUT $1"
    /bin/rm -f "$REST_CONFIGFILE_OUT"

    { echo "# setting root logger level to DEBUG with CONSOLE_APPENDER" ; echo "$rest_host_string" ; \
	echo "# algorithm used to crypt Private Key in PEM format" ; \
	echo "pemEncryption=AES-128-CFB" ; } \
	> "$REST_CONFIGFILE_OUT"

    cred_cli_log "$DEBUG" "wrote jboss rest file"

}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  jb_write_conf_files
#   DESCRIPTION:  this function write config file used by Jboss in order to comunicate
#                 with remote SPS via rest and secure interfaces
#    PARAMETERS:  $2 host numbers found
#       RETURNS:  none
#-------------------------------------------------------------------------------

jb_write_conf_files() {

    #short name for log

    size=$2
    local rest_addresses="address="
    local ip_addresses="hosts name are: "
    local remote_connections=""

    #following random index write ip founds

    for (( i=0; i< "$size"; i++ ));  do

	local_index=${random_index[$i]}
	ip=${ip_array_name[$local_index]}
	rest_addresses="$rest_addresses$ip:8080,"
	file=${host_array_name[$local_index]}

	ip_addresses="$ip_addresses $file "
	cred_cli_log "$INFO" "local_index=$local_index ip=$ip file=$file"

	remote_connections="$remote_connections $file,"
    done

    # now starts to prepare strings in order to write
    # on jboss config files

    #rest_addresses="$rest_addresses localhost:8080"
    #remote_connections="$remote_connections test"

    /bin/rm -f "$SECURE_JBOSS_CONFIGFILE_OUT"

    { echo "" ; echo "remote.connectionprovider.create.options.org.xnio.Options.SSL_ENABLED=true" ;
	echo remote.connections="$remote_connections" ;
	echo "" ; } > "$SECURE_JBOSS_CONFIGFILE_OUT"

    cred_cli_log  "$INFO" "hosts founds are=${host_array_name[*]} size= ${#host_array_name[*]}"

    for (( i=0; i< "$size"; i++ ));  do
	local_index=${random_index[$i]}
	cred_cli_log  "$DEBUG" "local_index=$local_index ${host_array_name[$local_index]}  ${ip_array_name[$local_index]}"

	echo "$JBOSS_SECURE_HOST"| sed -e "s/HOST/${host_array_name[$local_index]}/"| sed -e "s/IP/${ip_array_name[$local_index]}/"  >> "$SECURE_JBOSS_CONFIGFILE_OUT"
    done
    echo "$JBOSS_SECURE_HOST"| sed -e "s/HOST/test/"| sed -e "s/IP/localhost/"     >> "$SECURE_JBOSS_CONFIGFILE_OUT"

    wrt_write_rest_info "$rest_addresses"

    cred_cli_log "$DEBUG" "concluded"
}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  write_default_conf_file
#   DESCRIPTION:  this function writes in case of failure default conf files for jboss
#    PARAMETERS:  none   
#       RETURNS:  none
#-------------------------------------------------------------------------------

write_default_conf_file () {

    cp "$REST_CONFIGFILE_IN"         "$REST_CONFIGFILE_OUT"
    cp "$SECURE_JBOSS_CONFIGFILE_IN" "$SECURE_JBOSS_CONFIGFILE_OUT"
   
    cred_cli_log "$INFO" "copying default conf files"
}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  ip_names_resolver
#   DESCRIPTION:  this function looks to shared folder in order to find all SPS:SG 
#                 ip addresses , then it writes on jboss config files 
#    PARAMETERS:  none   
#       RETURNS:  number of hosts
#-------------------------------------------------------------------------------

ip_names_resolver() {

    # number of hosts (svc) used to calculate the memory allocation
    local hosts_number=$MEMORY_DEFAULT_HOSTS_NUMBER

    # find my api version reading on pom result file 
    my_version=$(property_resolver "$API_FILE_VERSION" version)
 
    cred_cli_log "$INFO" "cli-api version is $my_version"
    
    declare -a files_name

    # loop to check if there are any host files written from SPS
    loop=0
    maxLoop=2
    while [ "$loop" -le "$maxLoop" ]
    do
    	# now looks for shared foldr 
    	files_name=$(check_ip_files)
        if [ -z "$files_name" ]; then
            sleep 5
	    loop=$((loop+1))
	else
	    loop=$((maxLoop+1))
        fi
    done			

    # no files found returning...
    if [ -z "$files_name" ]; then
	if [ "$SAVE_DEFAULT_FILES" == "true" ] ; then 
            cred_cli_log "$ERROR" "not files found in ip conf dir; write default files"
	    write_default_conf_file
            return
	else
	    cred_cli_log "$ERROR" "no correct files found in ip conf dir; exiting "
	    exit "$EXIT_EMPTY_FOLDER"
	fi
    else
	cred_cli_log "$INFO" "ip_names_resolver -- $files_name found"
        
	# now for each files read related contents in order to read 
	# ip address and related api cred service managed

        pushd "$HOSTS_INFO_DIR" > /dev/null

        declare -A ip_array_name
        declare -A host_array_name
        
        declare i=0
        
        cred_cli_log "$INFO" "api_compatible_check conf value is $API_COMPATIBLE_CHECK"

        for file in $files_name; do
            
            ip=$(property_resolver "$file" ipv4)
            version=$(property_resolver "$file" version)
            
            cred_cli_log "$INFO" "found ip=$ip on file $file version=$version cli_version=$my_version"

            if [[ ("$API_COMPATIBLE_CHECK" == "false" ) || ( "$version" == "$my_version")  ]];  then

                cred_cli_log "$INFO" "write host=$file version=$version cli_version is $my_version"
                ip_array_name[$i]=$ip
                host_array_name[$i]=$file
                i=$((i + 1))

            else
                cred_cli_log "$INFO" "found different version and  API_COMPATIBLE_CHECK set to true -- discard $file"
            fi
        done 

        popd > /dev/null

	if [ "$i" == 0 ] ; then 
	    if [ "$SAVE_DEFAULT_FILES" == "true" ] ; then 
		cred_cli_log "$ERROR" "no correct files found; write default files"
		write_default_conf_file
	    else
		cred_cli_log "$ERROR" "no correct files found; exiting "
		exit "$EXIT_NO_API_AVAILABLE"
	    fi
	else
            # after saved ip:s and version:s now 
            declare -a random_index

            random_ind_creation $i random_index 

            jb_write_conf_files ip_array_name  $i

	    hosts_number=$i
	fi
    fi

    cred_cli_log "$DEBUG" "concluded"

    return $hosts_number

}

declare warningCheckDate=""


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  calculate_memory_usage
#   DESCRIPTION:  modify the global variable MEMORY_PARAMETERS adding the maximum value.
#                 It is calculated using the formula: base_value + step_value*number_of_hosts
#    PARAMETERS:  $1 = number of hosts 
#       RETURNS:  none 
#-------------------------------------------------------------------------------

calc_memory_usage() {

    local host_number=$1

    if [ $host_number -ge $MIN_HOSTS_NUMBER_TO_SCALE ]
    then
    	local max_value=$((MEMORY_BASE_VALUE+(MEMORY_STEP_VALUE*host_number) ))
    	MEMORY_PARAMETERS="${MEMORY_PARAMETERS/nnn/$max_value}"
    else
	MEMORY_PARAMETERS=$MEMORY_DEFAULT_PARAMETERS
    fi
	cred_cli_log "$DEBUG" "SVC number = $host_number"
	cred_cli_log "$INFO" "MEMORY PARAM is = $MEMORY_PARAMETERS"

}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  check_if_first_cron
#   DESCRIPTION:  this function checks if this script is called the first time of the day  
#    PARAMETERS:  none 
#       RETURNS:  none 
#-------------------------------------------------------------------------------

check_if_first_cron() {

    cred_cli_log "$DEBUG" "checking if it is the first run of the day"

    
    currentDate=$(date +%D)
    isHAcloud=""
    cred_cli_log "$DEBUG" "currentDate is $currentDate"

    if [ -e "$DATE_CLI_FILE" ]; then
        lastDate=$(property_resolver "$DATE_CLI_FILE" date)
        if [ "$lastDate" != "$currentDate" ]; then 
            warningCheckDate="$WARNING_CHECK_VALUE"
            cred_cli_log "$INFO" "found different date currentDate=$currentDate lastDate=$lastDate"
        else
            warningCheckDate=""
        fi   
    else
        warningCheckDate="$WARNING_CHECK_VALUE"
        cred_cli_log "$INFO" "not found date file.."
        isHAcloud=$(rpm -qa | grep ERICenmsghaproxy)
    fi


    if [ "$warningCheckDate" == "$WARNING_CHECK_VALUE" ] ; then 
        echo "date=$currentDate" > "$DATE_CLI_FILE"
        cred_cli_log "$INFO" "saving new date $currentDate"
    else
        cred_cli_log "$INFO" "date check found same dates..."
    fi

    if [ $isHAcloud ] ; then
        cred_cli_log "$INFO" "first check ever on haproxy ,skipping to avoid risky initial race condition"
        exit 0
    fi

}


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  purge_log_files 
#   DESCRIPTION:  this function checks if this script is called the first time of the day
#                 and in positive case it purges older cli java files   
#    PARAMETERS:  none 
#       RETURNS:  none 
#-------------------------------------------------------------------------------


purge_log_files() {

#    warningCheckDate="$WARNING_CHECK_VALUE"

    if [ "$warningCheckDate" == "$WARNING_CHECK_VALUE" ] ; then 

	# remove logs file older that X days 
	old_files=$(find "$JAVA_CLI_LOG_DIR"  -name 'CredentialManagerCLI*.log' -mtime +"$OLD_FILES_MAINTAIN")

        declare -a oldfiles_split_array
        local IFSOLD=' ' oldfiles_split_array=($old_files)
        cred_cli_log "$INFO" "We have to remove old logs files: ${#oldfiles_split_array[@]} files"
        for element in "${oldfiles_split_array[@]}"
                do
                   /bin/rm -rf "$element"
                done
        cred_cli_log "$INFO" "Remove old logs files done"
    fi

    return;
} 


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  check_copy_xml
#   DESCRIPTION:  this function checks if this script needs to copy xml in the shared folder 
#                 In positive case it looks to all xml files and copy then.
#    PARAMETERS:  none 
#       RETURNS:  none 
#-------------------------------------------------------------------------------

check_copy_xml() {


    if [ "$copyxmlfilesflag" == "true" ] ; then 

        cred_cli_log "$INFO" "We have to copy xml files"
#	shopt -s nullglob
	pushd "$XML_DIR" > /dev/null 
	for FILE in *.xml
        do
	    [[ -e $FILE ]] || break # handle the case of no *.xml files
	    cred_cli_log "$INFO" "Copying $FILE in $(hostname)_$FILE"
            rm -f "$XML_SHARED_DIR/$(hostname)_$FILE"
            cp "$FILE" "$XML_SHARED_DIR/$(hostname)_$FILE"
        done
        popd > /dev/null
        cred_cli_log "$INFO" "Copied all xml files "
    fi
    
    return;

} 


#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  kill_pending_cron
#   DESCRIPTION:  this function kills still running script instances in check mode;
#    PARAMETERS:  none
#       RETURNS:  none
#-------------------------------------------------------------------------------

kill_pending_cron() {

	local pid_strings; 
	pid_strings=$(ps -ef | grep  "$CLI_BIN_DIR/credentialmanager.sh" | grep -v grep | grep -v -e "--taf" | grep -v $$ | awk '{printf  "%s ", $2  }'  )

	cred_cli_log "$DEBUG" "mypid is=$$ my_parentPID= $PPID"
	cred_cli_log "$DEBUG" "pid found are= $pid_strings"

	declare -a pid_split_array
	local IFS=' ' pid_split_array=($pid_strings)
	
	cred_cli_log "$INFO" "pid size is ${#pid_split_array[@]}"

	if [[ "${#pid_split_array[@]}" -eq 0 ]] ; then 
	    cred_cli_log "$DEBUG" "no pids found to kill returning"
	    return ; 
	fi

	for element in "${pid_split_array[@]}"
	do
            if [[ ( $element -ne $$ ) && ( $element -ne $PPID )  ]]; then 

	    # now look for father/children eventually present 
		parentPid=$(ps -o ppid= -p "$element")
		prid=$(ps ax -o pid,pgid,ppid | grep "$element")
		prid=${prid//$element/}
		prid=${prid//$parentPid/}

		cred_cli_log  "$INFO" "process $element and related father $parentPid are going to be killed"
		cred_cli_log  "$INFO" "process $element father/children is/are $prid"

		kill -9  "$prid" 2>/dev/null

           #Addinf again killeng children process because we found hang child process on services.
       
                prid_bis=$(pgrep -P $element)
                declare -a pid_bis_split_array
                local IFSBIS=' ' pid_bis_split_array=($prid_bis)
                for child in "${pid_bis_split_array[@]}"
                do
                   kill -9 $child
                   cred_cli_log "$INFO" "killed BIS $child"
                done
 		
        
                kill -9  "$element" 2>/dev/null
                kill -9  "$parentPid" 2>/dev/null
                                    
            else
		cred_cli_log "$DEBUG" "skipping my process-id or parent process-id  $element"
            fi
	done
    return

}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  chk_this_proc_is_run
#   DESCRIPTION:  this function checks is another instance of this script is already running;
#                 is it finds it then it will be killed
#    PARAMETERS:  none
#       RETURNS:  none
#-------------------------------------------------------------------------------

chk_this_proc_is_run() {
 
    cred_cli_log "$DEBUG" "check_if_this_process_is_already_running"

    local install_strings; 
    install_strings=$(ps -ef | grep  "$CLI_BIN_DIR/credentialmanager.sh" | grep -e "-i" | grep -v grep | grep -v -e --taf | awk '{printf  "%s ", $2  }'  )

    cred_cli_log "$DEBUG" "install_strings = $install_strings"
    #is an install is running we exiting...

    if [[ -n "$install_strings" ]] ; then 
	cred_cli_log "$ERROR" "install processes are still running, exiting $install_strings"
	exit "$EXIT_INSTALL_RUNNING" 
    fi

    if [[ -e ${CRONTAB_LOCK_FILE} ]] ; then 

	cred_cli_log "$INFO" "found CRON LOCK... "

        kill_pending_cron

    fi
    touch "${CRONTAB_LOCK_FILE}" 
    cred_cli_log  "$INFO" "writing lock file for CRON"
    return 

}
#---  FUNCTION  ----------------------------------------------------------------                 
#          NAME:  manage_log_files
#   DESCRIPTION:                                                                                 
#                                                                                                
#    PARAMETERS:  none                                                                           
#       RETURNS:  none                                                                           
#-------------------------------------------------------------------------------                 

manage_log_files() {


    if [ "$1" == "true" ] ; then 

	cred_cli_log "$INFO" "add taf prefix to log dir path $LOG4_CONFFILE"

	sed -i 's/\/var\/log\/credentialmanager\/CredentialManagerCLI.log/\/var\/log\/credentialmanager\/taf\/CredentialManagerCLI.log/' "$LOG4_CONFFILE"
	sed -i 's/\/var\/log\/credentialmanager\/CredentialManagerCLIError.log/\/var\/log\/credentialmanager\/taf\/CredentialManagerCLIError.log/' "$LOG4_CONFFILE"
	#sed -i 's/\/var\/log\/credentialmanager\/CredentialManagerCLI.log/\/var\/log\/credentialmanager\/taf\/CredentialManagerCLI.log/' "$LOG4_ERROR_CONFFILE"
	#sed -i 's/\/var\/log\/credentialmanager\/CredentialManagerCLIError.log/\/var\/log\/credentialmanager\/taf\/CredentialManagerCLIError.log/' "$LOG4_ERROR_CONFFILE"
	sed -i 's/\/var\/log\/credentialmanager\/stdout.out/\/var\/log\/credentialmanager\/taf\/stdout.out/' "$LOG4_CONFFILE"

    else
	cred_cli_log "$INFO" "removing taf prefix to log dir path"

	sed -i 's/\/var\/log\/credentialmanager\/taf\/CredentialManagerCLI.log/\/var\/log\/credentialmanager\/CredentialManagerCLI.log/' "$LOG4_CONFFILE"
	sed -i 's/\/var\/log\/credentialmanager\/taf\/CredentialManagerCLIError.log/\/var\/log\/credentialmanager\/CredentialManagerCLIError.log/' "$LOG4_CONFFILE"
	#sed -i 's/\/var\/log\/credentialmanager\/taf\/CredentialManagerCLI.log/\/var\/log\/credentialmanager\/CredentialManagerCLI.log/' "$LOG4_ERROR_CONFFILE"
	#sed -i 's/\/var\/log\/credentialmanager\/taf\/CredentialManagerCLIError.log/\/var\/log\/credentialmanager\/CredentialManagerCLIError.log/' "$LOG4_ERROR_CONFFILE"
	sed -i 's/\/var\/log\/credentialmanager\/taf\/stdout.out/\/var\/log\/credentialmanager\/stdout.out/' "$LOG4_CONFFILE"

    fi

    

}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  checkif_sfs_ready
#   DESCRIPTION:  
#                 
#    PARAMETERS:  none
#       RETURNS:  none
#-------------------------------------------------------------------------------

checkif_sfs_ready() {

    status=0
    wait=0
    loop=1

    cred_cli_log "$INFO" "Checking sls ready waitMaxTime is $STARTUP_WAIT"

    while  [[  loop -eq 1  ]]
    do
	timeout 2 ls "$COMMON_SHARED_FOLDER" > /dev/null 2>& 1 
	status=$?
	if [ "$status" -eq 0 ]; then
	    cred_cli_log "$INFO" "Checking sls ready done result=$status"
	    return 0
	else
            cred_cli_log "$INFO" "SFS not ready - waiting attempt $wait"
            sleep 1
            let wait=$wait+1;
	fi
	if [ $wait -gt "$STARTUP_WAIT" ]; then
	    cred_cli_log "$ERROR " "SFS is not ready - timed out" 
	    return 1 
	fi
    done 

    
}

#---  FUNCTION  ----------------------------------------------------------------
#          NAME:  main_procedure
#   DESCRIPTION:  
#                 
#    PARAMETERS:  none
#       RETURNS:  none
#-------------------------------------------------------------------------------

main_procedure() {


    if [ -e $CLI_CONF_FILES ] ; then 
    # found internal cli file conf now we will read it 

# shellcheck source=/opt/ericsson/ERICcredentialmanagercli/conf/credentialmanagerconf.sh
        . "$CLI_CONF_FILES"
    else
	exit 1
    fi

    cred_cli_log "$INFO" "starting pid=$$"

    copyxmlfilesflag=false;
    runninglogreport=false

#    if [ -e "$CLI_GEN_CONF_FILE" ] ; then 
    # found internal cli file 
#	cred_cli_log "$INFO" "found shared conf file $CLI_GEN_CONF_FILE"
#        copyxmlfilesflag=true;
#    fi

    parameters="$*"
    space=" "

    installparameter=false
    cronparameter=false
    postinstallparameter=false

    # default variables setting 
    cronAllowed=true
    installAllowed=true 
    postInstallAllowed=true

    tafrunningparameter=false

    warningCheckDate=""

    declare -a resultwithfilter=""

    
    cred_cli_log "$INFO" "script parameters are:  ${parameters}"

    for f in $parameters
    do
	cred_cli_log "$DEBUG" "parameter is ${f}"
 
        if [[ ( ${f} == "--install" ) ||   (${f} == "-i" ) ]] ; then 
            cred_cli_log "$INFO" "found parameter --install/-i" 
            installparameter=true
        fi
        
        if [[ ( ${f} == "--check" ) ||   (${f} == "-c" ) ]] ; then 
            cred_cli_log "$INFO" "found parameter --check/-c" 
            cronparameter=true
        fi 

        if [[ ${f} == "--taf" ]] ; then
            cred_cli_log "$INFO" "find  parameter --taf removing  ..."
            tafrunningparameter=true           
            continue  # read next parameter  and skip the rest
        fi

	if [[ ${f} == "-b" ||   (${f} == "--backdoor" ) ]] ; then
            cred_cli_log "$INFO" "find parameter -b removing  ..."
            postinstallparameter=true
            #eventually kills cron instances triggered before -b -i mode is called to avoid race conditions
            kill_pending_cron
            continue  # read next parameter  and skip the rest                                                                                            
        fi

        resultwithfilter=${resultwithfilter[*]}${space}${f}
    done

    cred_cli_log "$DEBUG" "script parameters after filtering are:  ${resultwithfilter}"

#
# check if shared file-system is ready, if not exiting 
# 
    
    if ! checkif_sfs_ready  ;  then
	cred_cli_log "$ERROR" "sls not ready exiting.."
	exit 1;
    fi

#
# reading local conf file (if present) in order to understand what it is allowed or not
#

    if [ -e "$CRED_BEHAVIOUR_CONFFILE" ] ; then 
    # found file conf now we will read it 
    # shellcheck source=/etc/credm/conf.d/credentialManagerCliConfigurator
        .  "${CRED_BEHAVIOUR_CONFFILE}"
        cred_cli_log "$INFO" "read from conf local file ${CRED_BEHAVIOUR_CONFFILE}"
	cred_cli_log "$INFO" "installAllowed=$installAllowed cronAllowed=$cronAllowed postInstallAllowed=$postInstallAllowed"
    else
        cred_cli_log "$INFO" "Behaviour conf file not found using default values install,postInstall and cron are true"
        cred_cli_log "$INFO" "installAllowed=${installAllowed}, cronAllowed=${cronAllowed} postInstallAllowed=${postInstallAllowed}"
    fi

#
# reading shared conf file (if present) in order to understand what it is allowed or not
#

    if [ -e "$CRED_BEH_CONFFILE_OVERWRITE"  ] ; then 
    # found file conf overrite files now we will read it 
    # shellcheck source=/ericsson/tor/data/cred/conf/credentialManagerCliConfigurator
        .  "${CRED_BEH_CONFFILE_OVERWRITE}"
        cred_cli_log "$INFO" "read from shared file ${CRED_BEH_CONFFILE_OVERWRITE}"
	cred_cli_log "$INFO" "installAllowed=$installAllowed cronAllowed=$cronAllowed postInstallAllowed=$postInstallAllowed"
    else
        cred_cli_log "$INFO" "Behaviour shared file not found $CRED_BEH_CONFFILE_OVERWRITE"
    fi


#
# now check on what phrase are running and if we can go on...
#

    javarunningflag=false; 

    cred_cli_log  "$INFO" "checking if java appl can run"

# check on initialStartup


    if [[ ( "$installAllowed" == "true" ) && ( "$installparameter" == "true") && 
		( "$postinstallparameter" == "false" )]] ; then
#        if [[ ! -f $STOP_CRON_FILE ]] ; then
#            # STOP_CRON_FILE not present means that initial install is already run
#            javarunningflag=false
#            cred_cli_log  "$INFO" "found installAllowed and installparameter set to true but STOP_CRON_FILE not present: java initial install not allowed"
#        else
            javarunningflag=true; 
            cred_cli_log  "$INFO" "found installAllowed and installparameter set to true, java initial install allowed"
            if [ -f $STATE_FILE ] ; then
               cred_cli_log  "$INFO" "removed .state file"
               rm -f $STATE_FILE
#            fi
        fi
    fi

# check on  cron

    if [[ ( "$cronAllowed" == "true" ) && ( "$cronparameter" == "true" ) ]] ; then 
        javarunningflag=true; 
        cred_cli_log "$INFO" "found cronAllowed and cronparameter set to true, check crontab stuff"
        if [[ ( "$installAllowed" == "true" ) && ( -f $STOP_CRON_FILE ) ]] ; then
            cred_cli_log "$INFO" "Found cron lock file for VM, cron will be not executed to wait for install to finish running"
            javarunningflag=false;
        fi
    fi

    manage_log_files "$tafrunningparameter"

# check is backdoor  parameter is present 

    if [[ ( "$postinstallparameter" == "true" ) && ( "$postInstallAllowed" == "true") && 
		( "$installparameter" == "true") ]] ; then 
        javarunningflag=true; 
        cred_cli_log "$INFO" "found postinstallparameter and postInstallAllowed set to true"
    fi

    cred_cli_log "$DEBUG" "postinstallparameter=$postinstallparameter"

# check is taf flag is present 

    if [[ "$tafrunningparameter" == "true" ]] ; then
	javarunningflag=true;
        cred_cli_log "$INFO" "found tafrunningparameter allowed to run java .."
    fi

    cred_cli_log "$DEBUG" "tafrunning=$tafrunningparameter"

# for log on shared folder ...
    if [ "$runninglogreport" == "true" ] ; then 
	echo -e "$(date +[%D-%T])  HOST=$(hostname) $ip_addresses in=$installparameter cron=$cronparameter javarunningflag=$javarunningflag" >> $LOG_HOST_DIR/cli_log.txt
    fi


# if it is not allowed we exit

    if [ $javarunningflag == "false" ] ;  then 
        cred_cli_log  "$WARN" "exiting not running java pid=$$"
        exit "$EXIT_JAVA_NOT_ALLOWED_TO_RUN"
    fi

    cred_cli_log "$INFO" "javarunningflag is $javarunningflag"

# we are on cron stuff ?  

    if [[  ("$tafrunningparameter" == "false" ) && ( "$cronAllowed" == "true" ) && ( "$cronparameter" == "true" ) ]] ; then 
        cred_cli_log "$INFO" "On cron stuff we have to check: if we can run, if are running first time on the day"
        cred_cli_log "$INFO" "if necessary purge files and copy xml files"
	    chk_this_proc_is_run
        check_if_first_cron 
	    purge_log_files
	    check_copy_xml
    fi

    
    # now look to shared folder in order to find ip addresses
    ip_names_resolver
    memory_hosts_number=$?
    # retrieve the number of SPSs from the previous function

    #prepare MEMORY_PARAMETERS value using number of hosts found
    calc_memory_usage $memory_hosts_number

    cred_cli_log "$INFO" "running javacredentialmanagercli..."

    if [[ "$memory_checker" == "true" ]] ; then

	cred_cli_log "$INFO" "running memory checker ..."
        /opt/ericsson/ERICcredentialmanagercli/bin/memorychecker.sh $$   >> /tmp/cli_memory_report/cli_memory_report.txt 2>> /dev/null   &
    fi


    java $MEMORY_PARAMETERS  $JAVA_PARAMETERS ${resultwithfilter[*]} "${warningCheckDate}"  

    returncode=$?

    if [[ ( "$installAllowed" == "true" ) && ( "$installparameter" == "true") &&
                ( "$postinstallparameter" == "false" )]] ; then
        cred_cli_log "$INFO" "Finished install on VM, check on lock to allow --check"
        if [ -f $STOP_CRON_FILE ] ; then
            cred_cli_log  "$INFO" "removing lock, --check allowed from this point onward"
            rm -f $STOP_CRON_FILE
        fi
    fi

    if [[ ("$tafrunningparameter" == "false" )  && ( "$cronparameter" == "true" ) ]] ; then 
	cred_cli_log "$INFO" "remove lock file for CRON"
	/bin/rm -f  "${CRONTAB_LOCK_FILE}"
    fi

    if [ $returncode -eq 0 ]; then 
        cred_cli_log "$INFO" "done pid=$$"
        exit "$EXIT_OK"
    else
        cred_cli_log "$ERROR" "java cli returned an error $returncode pid=$$"
        exit "$returncode"
    fi
}


#test_procedure() {

#    . source.sh 
#    cred_cli_log ""$INFO"" "starting"
#    manage_log_files false
#    chk_this_proc_is_run
#    ip_names_resolver
#chk_first_run_month

#purge_log_logs
    
#    check_if_first_cron

#    cred_cli_log ""$INFO"" "end"



#}

#starting from here execution 

main_procedure "$@"

# test scripts used on local env 
#if [ `hostname` == "centos" ] ; then 
    #test_procedure
#    if [ $1 == "loop" ] ; then 

#	while :
#	do
#	    /usr/java/jdk1.7.0_60/bin/java -Dfile.encoding=UTF-8 -classpath /home/enmadmin/wks_example/loopprova/bin loopprova.prova1  >> /tmp/loop.$$
#	done
#    fi
#else
#    main_procedure "$@"
#fi


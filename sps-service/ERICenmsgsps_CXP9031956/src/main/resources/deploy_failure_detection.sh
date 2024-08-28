#!/bin/bash
RM=/bin/rm
SED=/bin/sed
CHMOD=/bin/chmod
CP=/bin/cp
MKDIR=/bin/mkdir
SUDO=/usr/bin/sudo
JCMD=/usr/java/default/bin/jcmd
JPS=/usr/bin/jps
TMP=/tmp
EXEC_WITH_USER="$SUDO su jboss_user -c"

JBOSS_HOME=/ericsson/3pp/jboss
HC_CONF_FILE=/etc/simple_availability_manager_agents/config/healthcheck.ini
PATH_THREAD_DUMP=/ericsson/enm/dumps
SCRIPT_NAME="${BASENAME} ${0}"

LOG_TAG="DEPLOY_FAILURE_DETECTION"
ERR_FATAL1="JBAS015957: Server boot has failed"
ERR_FATAL2="JBAS013412: Timeout after"

#///////////////////////////////////////////////////////////////
# This function will print an error message to /var/log/messages
# Arguments:
#       $1 - Message
# Return: 0
#//////////////////////////////////////////////////////////////
error()
{
    logger -s -t ${LOG_TAG} -p user.err "ERROR ( ${SCRIPT_NAME} ): $1"
}

#//////////////////////////////////////////////////////////////
# This function will print an info message to /var/log/messages
# Arguments:
#       $1 - Message
# Return: 0
#/////////////////////////////////////////////////////////////
info()
{
    logger -s -t ${LOG_TAG} -p user.notice "INFORMATION ( ${SCRIPT_NAME} ): $1"
}

check_fatal_error()
{
   format="+%s"
   now=$(date $format)

   faults=$(grep -e "$ERR_FATAL1" -e "$ERR_FATAL2" $JBOSS_HOME/standalone/log/server.log |awk '{print $1" "$2}')
   if [[ -n $faults ]]; then
      threshold="60"
      while read -r line; do
         fault=$(date -d "$line" $format)
         diff=$((now - fault))
         if [ $diff -le $threshold ] ; then
            error "Found FATAL error in server.log"
            update_conf=1
            break;
         fi
      done <<< "$faults"
   fi
}

save_thread_dumps()
{
   $MKDIR -p $TMP/$(hostname)
   $CHMOD 777 $TMP/$(hostname)
   PIDS=$($EXEC_WITH_USER "$JCMD -l" |grep jboss-module | awk '{print $1}')
   for PID in $PIDS ; do
    $EXEC_WITH_USER "$JCMD $PID Thread.print" > $TMP/$(hostname)/$(hostname)_${PID}_`date +%Y-%m-%d.%H:%M:%S`.td
   done

   $JPS > $TMP/$(hostname)/jps
   cat /var/run/jboss/jboss.pid > $TMP/$(hostname)/jboss.pid

   tar -C $TMP -czvf $TMP/$(hostname).tgz $(hostname)
   $CP $TMP/$(hostname).tgz $PATH_THREAD_DUMP
}

update_conf=0

isdeploying_DEs=$(find $JBOSS_HOME/standalone/deployments \( -type f -iname '*.isdeploying' \))
isdeploying_DEs_COUNT=$(echo "$isdeploying_DEs" | wc -w)
isdeployed_DEs=$(find $JBOSS_HOME/standalone/deployments \( -type f -iname '*.deployed' \))
isdeployed_DEs_COUNT=$(echo "$isdeployed_DEs" | wc -w)

if [ "$isdeploying_DEs_COUNT" -gt 0 ] || [ "$isdeployed_DEs_COUNT" -eq 0 ]; then
   check_fatal_error
   if [ $update_conf -eq 1 ] ; then
       error "Detected deployment timeout. Reducing allowedStartupTime to 601 secs."
       ${SED} -i '/^\[SERVICE_HA_CONFIG\]$/,/^\[/ s/^[ \t]*allowedStartupTime.*/allowedStartupTime: 601/' ${HC_CONF_FILE}
       save_thread_dumps
       ${RM} /usr/lib/ocf/resource.d/deploy_failure_detection.sh
   fi
fi

failed_undeployed_DEs=$(find $JBOSS_HOME/standalone/deployments \( -type f -iname '*.failed' -o -iname '*.undeployed' \) -a ! -iname "dps-jpa-ear-runtime*")
failed_undeployed_DEs_COUNT=$(echo "$failed_undeployed_DEs" | wc -w)

if [ "$failed_undeployed_DEs_COUNT" -gt 0 ]; then
    error "Detected failures in applications deployment. Reducing allowedStartupTime to 601 secs."
    ${SED} -i '/^\[SERVICE_HA_CONFIG\]$/,/^\[/ s/^[ \t]*allowedStartupTime.*/allowedStartupTime: 601/' ${HC_CONF_FILE}
    info "All Failed Undeployed DE list: $failed_undeployed_DEs"
    save_thread_dumps
    ${RM} /usr/lib/ocf/resource.d/deploy_failure_detection.sh
fi

exit 0

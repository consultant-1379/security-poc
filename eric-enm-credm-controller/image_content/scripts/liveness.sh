#!/bin/bash

TIMESTAMP1=`date +%Y-%m-%d`
TIMESTAMP2=`date +%Y-%m-%d:%H:%M:%S`
LOG_PATH="/var/log/credmcontroller/liveness_probe"
LOG_FILE=${LOG_PATH}_${TIMESTAMP1}.log


#############################################
# Action :
#   checkRsyslogStatus
# Arguments:
#   None
# Returns:
#   Return code of rsyslog status
############################################
RSYSLOG_HEALTH_CHECK="/usr/lib/ocf/resource.d/rsyslog-healthcheck.sh"
checkRsyslogStatus(){

  if [[ ! -f $RSYSLOG_HEALTH_CHECK ]]; then
     echo "Rsyslog health check is not installed" >> $LOG_FILE
     return 0
  fi
  $RSYSLOG_HEALTH_CHECK
  RETCODE=$?
  if [[ ${RETCODE} != 0 ]] ; then
    echo "Rsyslog healthcheck: has failed" >> $LOG_FILE
    return 1
  fi
  echo "Rsyslog healthcheck: OK" >> $LOG_FILE
  return 0
}

# LIVENESS for CREDM CONTROLLER

# purge old log files
if [ ! -f $LOG_FILE ]; then
   rm `ls -t ${LOG_PATH}_* | awk 'NR>10'`
   echo $TIMESTAMP1 > $LOG_FILE
fi

# liveness

  echo "-------------" >> $LOG_FILE
  echo "init liveness" >> $LOG_FILE
  echo $TIMESTAMP2 >> $LOG_FILE
  
  # check process exists
  echo "check PID" >> $LOG_FILE
  pidFile=`cat /credm/pid.id`
  echo "pid file:$pidFile" >> $LOG_FILE
  res=`ps -aux | grep gunicorn | wc -l`
  echo "ps res=$res" >> $LOG_FILE
  if [ $res < 2 ]
  then
    echo "FAIL" >> $LOG_FILE
	exit 1
  fi

  # check rsyslog health
  echo "check rsyslog" >> $LOG_FILE
  checkRsyslogStatus
  RETCODE=$?
  if [[ ${RETCODE} != 0 ]] ; then
      return 1
  fi

  exit 0

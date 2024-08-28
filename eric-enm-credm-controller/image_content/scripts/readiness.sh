#!/bin/bash

TIMESTAMP1=`date +%Y-%m-%d`
LOG_PATH="/var/log/credmcontroller/readiness_probe"
LOG_FILE=${LOG_PATH}_${TIMESTAMP1}.log
READY_TIMEOUT=120

# READINESS for CREDM CONTROLLER

if [ ! -f $LOG_FILE ]; then
   rm `ls -t ${LOG_PATH}_* | awk 'NR>10'`
   echo $TIMESTAMP1 > $LOG_FILE
fi

  echo "-------------" >> $LOG_FILE
  echo "init readiness" >> $LOG_FILE
  TIMESTAMP2=`date +%Y-%m-%d:%H:%M:%S`
  echo $TIMESTAMP2 >> $LOG_FILE

  OUTPUT_STRING=`curl -m ${READY_TIMEOUT} http://localhost:$REST_PORT/ping`
  res=$?
  echo "curl res=$res" >> $LOG_FILE
  echo "curl return=$OUTPUT_STRING" >> $LOG_FILE
  TIMESTAMP3=`date +%Y-%m-%d:%H:%M:%S`
  echo $TIMESTAMP3 >> $LOG_FILE

  if [ $res != 0 ]
  then
    echo "FAIL" >> $LOG_FILE
	exit 1
  fi
  exit 0

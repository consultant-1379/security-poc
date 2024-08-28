#!/bin/bash

# env: CONTROLLER_NAME
# env: CONTROLLER_PORT
# env: SERVICENAME
# env: HOOKACTION
# env: HOOKNAME

READY_TIMEOUT=10
READY_SLEEP=5
READY_SLEEP_BASE=5
REQ_TIMEOUT=240
REQ_SLEEP=10
REQ_SLEEP_BASE=10

echo "$SERVICENAME service Certificates Request JOB"

echo "first CURL to wait for credm READY"
res=-1
while [ $res -ne 0 ]
do
  echo "..."
  now=$(date +"%T")
  echo "Current time : $now"
  echo "check Controller readiness"
  echo "CONTROLLER_NAME:"$CONTROLLER_NAME
  echo "CONTROLLER_PORT:"$CONTROLLER_PORT
  OUTPUT_STRING=`curl -m ${READY_TIMEOUT} ${CONTROLLER_NAME}:${CONTROLLER_PORT} 2>/dev/null`
  res=$?
  echo "Result of rest : "$res
  echo "random pause"
  sleep $[ ( $RANDOM % $[$READY_SLEEP] )  + $[$READY_SLEEP_BASE] ]s
done

echo "..."
echo "CREDM CONTROLLER READY"

res=-1
while [ $res -ne 0 ]
do
  echo "..."
  now=$(date +"%T")
  echo "Current time : $now"
  echo "call Controller from "$HOOKNAME
  echo "CONTROLLER_NAME:"$CONTROLLER_NAME
  echo "CONTROLLER_PORT:"$CONTROLLER_PORT
  echo "SERVICENAME:"$SERVICENAME
  echo "ACTION:"$HOOKACTION
  # send with the request also the current time plus the timeout, in order to discard the request if too old
  dateInsec=$(date +"%s")
  echo "Current time in seconds: $dateInsec"
  echo "Timeout: ${REQ_TIMEOUT}"
  #OUTPUT_STRING=`curl -m ${REQ_TIMEOUT} ${CONTROLLER_NAME}:${CONTROLLER_PORT}/${HOOKACTION}/${SERVICENAME} 2>/dev/null`
  OUTPUT_STRING=`curl -m ${REQ_TIMEOUT} ${CONTROLLER_NAME}:${CONTROLLER_PORT}/${HOOKACTION}/${SERVICENAME}/${dateInsec}/${REQ_TIMEOUT} 2>/dev/null`
  res=$?
  now2=$(date +"%T")
  echo "response time : $now2"
  echo "Result of rest : "$res
  echo "String returned by Credm Controller: "$OUTPUT_STRING
  if [[ $OUTPUT_STRING == "" ]]; then
    echo "..."
    echo "Credm Controller not yet active: try again ..."
  fi
  if [[ $OUTPUT_STRING == *"NOT_OK"* ]]; then
    res=1
    echo "..."
    echo "Result of rest is NOT OK: try again ..."
  fi
  if [[ $OUTPUT_STRING == *"Error"* ]]; then
    res=2
    echo "..."
    echo "Result of rest is ERROR: try again ..."
  fi
    
  echo "random pause"
  sleep $[ ( $RANDOM % $[$REQ_SLEEP] )  + $[$REQ_SLEEP_BASE] ]s
  
done

echo "exit hook"

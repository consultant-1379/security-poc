#!/bin/bash

# env: CONTROLLER_NAME
# env: CONTROLLER_PORT
# env: SERVICENAME
# env: HOOKACTION
# env: HOOKNAME

CONTROLLER_NAME="eric-enm-credm-controller"
CONTROLLER_PORT=5001
SERVICENAME=$1
HOOKACTION="certRequest"
HOOKNAME="listener"

echo "$SERVICENAME service Certificates Request JOB"

res=-1
#sleep 10
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
  OUTPUT_STRING=`curl -m 240 ${CONTROLLER_NAME}:${CONTROLLER_PORT}/${HOOKACTION}/${SERVICENAME} 2>/dev/null`
  res=$?
  echo "Result of rest : "$res
  echo "String returned by Credm Controller: "$OUTPUT_STRING
  if [[ $OUTPUT_STRING == "" ]]; then
    echo "..."
    echo "Credm Controller not yet active: try again ..."
    sleep 10
  fi
  if [[ $OUTPUT_STRING == *"NOT_OK"* ]]; then
    res=1
    echo "..."
    echo "Result of rest is NOT OK: try again ..."
    sleep 10
  fi
  if [[ $OUTPUT_STRING == *"Error"* ]]; then
    res=2
    echo "..."
    echo "Result of rest is ERROR: try again ..."
    sleep 10
  fi
done

echo "exit hook"

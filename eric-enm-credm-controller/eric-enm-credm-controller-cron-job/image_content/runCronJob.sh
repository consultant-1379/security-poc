#!/bin/bash

# CONSTANTS
SLEEP_SERVICE_LIST=2
SLEEP_CHECK=1
TIMEOUT_SERVICE_LIST=240
TIMEOUT_CHECK=240
CRONJOBSTATE_REST=cronJobState
CRONJOBSTATE_START=start
CRONJOBSTATE_STOP=stop
GETSERVICELIST_REST=getServicesListWithCertificates
PERIODICCHECK_REST=periodicCheck

echo "CREDM CONTROLLER CRON JOB starting ..."
echo "CONTROLLER_NAME: "$CONTROLLER_NAME
echo "CONTROLLER_PORT: "$CONTROLLER_PORT
echo "..."

set_cronjob_state () {
  echo "Set CronJob State $1"
  RESULT=`curl -m ${TIMEOUT_SERVICE_LIST} ${CONTROLLER_NAME}:${CONTROLLER_PORT}/${CRONJOBSTATE_REST}/$1 2>/dev/null`
  res=$?
  echo "Result of rest for set state: "$res
  echo "String returned for get by Credm Controller: "$RESULT
  echo "..."
}

#echo "check certrequest jobs"
#echo "namespace : "$NAMESPACE
#
#kubectl get job -n $NAMESPACE | grep certrequest-job
#
#declare -a listJob
#
#listJob=$(kubectl get job -n $NAMESPACE | grep certrequest-job | awk '{print $1}')
#for i in $listJob; 
#do 
#    echo $i
#    kubectl get pods -n $NAMESPACE | grep $i 
#    njc=$(kubectl get pods -n $NAMESPACE | grep $i | grep Completed | wc -l)
#    if [[ $njc != 0 ]]
#    then
#	echo "found completed job: delete it"
#	kubectl delete job $i -n $NAMESPACE
#    fi
#done
#echo "end of check certrequest jobs"

declare -a SERVICES_LIST_ARRAY 

# cron job start
set_cronjob_state $CRONJOBSTATE_START

res=-1
while [ $res -ne 0 ]
do
  echo "call Credm Controller to get the list of services that need for certificates"

  # get list of services to check
  SERVICES_LIST_STRING=`curl -m ${TIMEOUT_SERVICE_LIST} ${CONTROLLER_NAME}:${CONTROLLER_PORT}/${GETSERVICELIST_REST} 2>/dev/null`
  res=$?
  echo "Result of rest for get service: "$res
  echo "String returned for get by Credm Controller: "$SERVICES_LIST_STRING
  if [[ $SERVICES_LIST_STRING == *"NOT_OK"* ]]; then
    res=1
    echo "Result of rest for get is NOT OK: try again ..."
  fi
  echo "..."
  sleep $SLEEP_SERVICE_LIST
done

# prepare list
SERVICES_LIST_STRING="$(echo "$SERVICES_LIST_STRING" | sed 's,\[,,' | sed 's,\],,' | sed 's/\"//g')"
echo "String after sed command: "$SERVICES_LIST_STRING
echo "..."

IFS=',' read -ra SERVICES_LIST_ARRAY <<< "$SERVICES_LIST_STRING"

# check for each service
for service in "${SERVICES_LIST_ARRAY[@]}"; do
  echo "call Credm Controller to execute cron check for service: "$service
  OUTPUT_STRING=`curl -m ${TIMEOUT_CHECK} ${CONTROLLER_NAME}:${CONTROLLER_PORT}/${PERIODICCHECK_REST}/${service} 2>/dev/null`
  res=$?
  echo "Result of rest for periodic check: "$res
  echo "String returned for execution by Credm Controller: "$OUTPUT_STRING
  echo "..."
  sleep $SLEEP_CHECK
done

# cron job end
set_cronjob_state $CRONJOBSTATE_STOP

echo "exit from CRON JOB"

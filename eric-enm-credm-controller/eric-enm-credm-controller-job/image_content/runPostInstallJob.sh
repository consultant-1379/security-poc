#!/bin/bash

# env: NAMESPACE
SLEEP_TIME=10
SECRET_SELECTOR=certRequest
SECRET_GREP=certreq
JOB_GREP=certrequest-job

echo "CREDM CONTROLLER POST-INSTALL JOB starting ..."
echo "namespace : "$NAMESPACE


# check if there are any certrequest secrets
kubectl get secret --selector=${SECRET_SELECTOR}=true -n $NAMESPACE
nSecret=$(kubectl get secret --selector=${SECRET_SELECTOR}=true  -n $NAMESPACE | grep ${SECRET_GREP} | wc -l)
echo "number of certrequest secrets : $nSecret"

# if no secrets exit
if [[ $nSecret == 0 ]]
then
    echo "no secrets: EXIT"
    exit 0
fi

flag=-1
# wait until all job are completed
while [ $flag -ne 0 ]
do
    sleep $SLEEP_TIME

    echo "check"
    # number of certrequest-job
    echo "JOB list"
    kubectl get job -n $NAMESPACE| grep ${JOB_GREP}
    nJob=$(kubectl get job -n $NAMESPACE | grep ${JOB_GREP} | wc -l)
    # number of certrequest-job PODd completed
    echo "JOB POD list"
    kubectl get pods -n $NAMESPACE | grep ${JOB_GREP}
    nCompleted=$(kubectl get pods -n $NAMESPACE | grep ${JOB_GREP} | grep Completed | wc -l)

    echo "number of certrequest-job JOB : $nJob  completed PODs : $nCompleted"

    if [[ $nJob == 0 ]]
    then
        echo "all JOBS already deleted"
        flag=0
    else
      if [[ $nCompleted -ge $nJob ]]
      then
        echo "all completed"

	echo "stop certrequest-job JOBs"
	kubectl get job -n $NAMESPACE | grep ${JOB_GREP} | awk '{print $1}'
	kubectl delete job $(kubectl get job -n $NAMESPACE | grep ${JOB_GREP} | awk '{print $1}') -n $NAMESPACE

      fi
    fi
done

echo "end of CREDM CONTROLLER POST-INSTALL JOB"

sleep $SLEEP_TIME





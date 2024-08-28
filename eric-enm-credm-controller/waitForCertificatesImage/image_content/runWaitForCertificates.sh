#!/bin/bash

# SCRIPT FOR WAITFORCERTIFICATS init container
#
# required env values (to be defined in service deployment.yaml):
#
# SERVICE_NAME (defined in .Values.service.name)
# XML_MOUNT_PATH (defined in .Values.service.xmlMountPath)
#
# the script looks inside XML_MOUNT_PATH subdirectories  
# for each subdirectory it need to find READY state

echo "INIT/WAIT container for $SERVICE_NAME service: looking for certReq"

# from deployment.yaml
XML_DIR=$XML_MOUNT_PATH
XML_STATE=certReqState
XML_READY=ready
SLEEP_TIME=5

scan_readystate () {

  # counters for directory and ready state
  certReqCounter=0
  certReqReady=0

  #
  echo "loop in ${XML_DIR}"
  for i in ${XML_DIR}/*
  do
    echo "$i found"
    if [ -d $i ]; then
          
	  echo "$i is a mount point directory"
          certReqCounter=$((certReqCounter+1))
          
	  # loop inside the folder
          for j in $i/*
          do
            echo "$j found"
            if [[ $j == *"${XML_STATE}"* ]]; then
                  # check state
                  echo "content of $j is $(cat $j)"
                  if [[ $(cat $j) == "${XML_READY}" ]]; then
                    echo "READY state found"
                    # increment ready state counter
                    certReqReady=$((certReqReady+1))
                  fi
            fi
          done
    fi
  done

  # check result
  echo "certReqCounter = $certReqCounter"
  echo "certReqReady = $certReqReady"

  if [ $certReqReady -gt 0 ]; then
    if [ $certReqCounter == $certReqReady ]; then
      return 0
    fi
  fi
  return -1
}

while true
do
  echo "----"
  scan_readystate
  res=$?
  echo "res = $res"
  if [  $res == 0 ]; then
        echo "all ready states found for $SERVICE_NAME service: OK"
        break
  fi
  sleep $SLEEP_TIME
done

echo "wait to terminate"
sleep $[ ( $RANDOM % 10 )  + 1 ]s
echo "end"


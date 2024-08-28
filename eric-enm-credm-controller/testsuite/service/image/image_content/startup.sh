#!/bin/bash


# SCRIPT to be put in the startup phase of service container
#
# required env values (to be defined in service deployment.yaml):
#
# SERVICE_NAME (defined in .Values.service.name)
# TLS_MOUNT_PATH (defined in .Values.service.tlsMountPath)
#
# the script looks inside TLS_MOUNT_PATH subdirectories  
# for each subdirectory searches for valid data inside
# when all data is present, it creates the required links to wanted positions

echo "startup $SERVICE_NAME"

# from deployment.yaml
TLS_DIR=$TLS_MOUNT_PATH
TLS_TYPE=tlsStoreType
TLS_LOCATION=tlsStoreLocation
TLS_DATA=tlsStoreData
TLS_FILE=file
TLS_NONE=none
SLEEP_TIME=5


scan_tlslocation () {

  # counters for directory and ready state
  tlsSecretCounter=0
  tlsLocationCounter=0

  #
  echo "loop in ${TLS_DIR}"
  for i in ${TLS_DIR}/*
  do
    echo "$i found"
    if [ -d $i ]
    then
	  echo "$i is a mount point directory"
	  tlsSecretCounter=$((tlsSecretCounter+1))
	  # loop inside the folder
	  for j in $i/*
      do
	    echo "$j found"
	    if [[ $j == *"${TLS_LOCATION}"* ]]
	    then
          # check type
          if [[ -f ${i}/${TLS_TYPE} ]]
          then
            echo "tlsType file found"
            if [[ $(< ${i}/${TLS_TYPE}) == "${TLS_FILE}" ]]
            then
              echo "Type of Secret is FILE"
		      # check contents
		      echo "content of $j is $(< $j)"
		      if [[ $(< $j) != "${TLS_NONE}" ]]
              then
		        echo "valid LOCATION found"
		        # increment ready state counter
		        tlsLocationCounter=$((tlsLocationCounter+1))
              fi
            fi
	  fi
        fi
      done
    fi	
  done

  # check result
  echo "tlsSecretCounter = $tlsSecretCounter"
  echo "tlsLocationCounter = $tlsLocationCounter"
  
  if [ $tlsLocationCounter -gt 0 ]
  then
    if [ $tlsSecretCounter == $tlsLocationCounter ]
    then
      return 0
    fi
  fi
  return -1
}

while true
do
  echo "----"
  scan_tlslocation
  res=$?
  echo "res = $res"
  if [  $res == 0 ]
  then
    echo "all locations found: OK"
	break
  fi
  sleep $SLEEP_TIME
done

# make links to keystores
for i in ${TLS_DIR}/*
do
    if [ -d $i ]
    then
      if [[ $(< ${i}/${TLS_TYPE}) == "${TLS_FILE}" ]]
      then
        tlsFilename=$(cat ${i}/${TLS_LOCATION})
        # test directory exist ansd creation
        tlsDirName="$(dirname "${tlsFilename}")"
        if [ ! -d "$tlsDirName" ]; then
            echo "$tlsDirName does not exist: create it"
            mkdir -p $tlsDirName
        fi
        echo "MAKE LINKS"
        echo ${tlsFilename}
        ln -s ${i}/${TLS_DATA} ${tlsFilename}
      else
        echo ${i}/${TLS_TYPE}
        echo "TLSSECRET type not FILE: do nothing"
      fi
    fi
done

echo "------------ end of init"

# JUST TO TEST
echo ""
tlsFilename=$(cat ${TLS_DIR}/tls1/${TLS_LOCATION})
#tlsFilename=/ericsson/credm/district11/certs/jbossKS.JKS
echo "---------------"
echo KEYSTORE
echo $tlsFilename
echo "---------------"
keytool -list -v -keystore ${tlsFilename} -alias jboss -storepass jbossKS
echo "---------------"
while true
do
    echo "---------------"
    echo CHECK SECRET MOUNT VALUES
    for i in ${TLS_DIR}/*
    do
        echo "FOLDER : "$i
        tlsFilename=$(cat ${i}/${TLS_LOCATION})
        echo $tlsFilename
        echo "---------------"
    done
    sleep 5
done





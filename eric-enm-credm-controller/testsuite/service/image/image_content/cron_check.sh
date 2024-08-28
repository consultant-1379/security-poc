#!/bin/bash

echo "CRON CHECK"

XML_DIR=/tmp/myxml-1
XML_STATE=certReqState
SECRET_DIR=/tmp/mytls-1
SECRET_STATE=tlsStoreState
SECRET_JSON=tlsStoreJsonData
KEYSTORE_FILE=/tmp/certs/jbossKS.jks
CRON_CHECK_SCRIPT=/tmp/cron_check.sh
CRON_CHECK_LOG=/tmp/cron.log
MD5_CHECK_FILE=/tmp/checkSecret.md5

# prepare first md5 check file
md5sum ${SECRET_DIR}/${SECRET_JSON} > ${MD5_CHECK_FILE}
echo "first md5 check file"
cat ${MD5_CHECK_FILE}

while true
do
  echo "----"
  date
  ps -aux
  echo "----"
  keystoreReady=$(cat ${SECRET_DIR}/${SECRET_STATE})
  echo $keystoreReady
  if [ $keystoreReady != "ready" ]; then
    sleep 10
  else
    echo "KEYSTORE IS NOW PRESENT..continue"
    break
  fi
done

sleep 2

# NOW THE TLS SECRET IS PRESENT
while true
do
  echo "----"
  date
  ps -aux
  echo "----"

  # check md5
  md5check=$(md5sum -c ${MD5_CHECK_FILE})
  echo "md5 check: "$md5check
  md5ok=$(echo $md5check | grep OK | wc -l)
  #echo $md5ok
  if [ "$md5ok" == "1" ]; then
    echo "MD5 OK"
  else
    #keystoreData=$(cat ${SECRET_DIR}/${SECRET_JSON})
    echo "---------------"
    echo update KEYSTORE
    echo "---------------"
 
    # extract and write keystores
    #echo $keystoreData | base64 --decode > /tmp/${keystoreName}
    cat ${SECRET_DIR}/${SECRET_JSON} | python3 /tmp/tlsFileExtract.py
    echo "---------------"

    # we know the keystore is in jboss.jks  
    echo "---- read keystore ------" 
    keytool -list -v -keystore ${KEYSTORE_FILE} -alias jboss -storepass jbossKS

    # update md5 check file
    md5sum ${SECRET_DIR}/${SECRET_JSON} > ${MD5_CHECK_FILE}
    cat ${MD5_CHECK_FILE}
  fi  
  sleep 30
done




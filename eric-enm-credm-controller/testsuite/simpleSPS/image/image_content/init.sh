#!/bin/bash

echo "init SIMPLE SERVICE"

XML_DIR=/tmp/myxml-1
XML_STATE=certReqState
TLS_DIR=/tmp/mytls-1
TLS_NAME=tlsStoreName
TLS_DATA=tlsStoreData

echo "waiting for secret"
while [ ! -d $TLS_DIR ]
do
  echo "secret not exist"
  sleep 2 
done
echo "secret exist"

while true
do
  echo "----"
  certReqReady=$(cat ${XML_DIR}/${XML_STATE})
  echo $certReqReady
  if [ $certReqReady != "ready" ]; then
    sleep 10
  else
    echo "KEYSTORE IS NOW PRESENT.."
    break
  fi
done

# make link to keystore 
tlsFilename=$(cat ${TLS_DIR}/${TLS_NAME})
echo "MAKE LINK"
echo ${tlsFilename}
ln -s ${TLS_DIR}/${TLS_DATA} ${tlsFilename}

while true
do
    echo "---------------"
    echo KEYSTORE
    echo "---------------"

    keytool -list -v -keystore ${tlsFilename} -alias jboss -storepass jbossKS
    sleep 60

done


echo "end of init"




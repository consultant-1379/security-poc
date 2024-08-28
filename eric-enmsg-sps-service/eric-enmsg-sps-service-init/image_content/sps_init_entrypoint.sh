#!/bin/bash

cp -f /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/data/certs/CredMService.jks    /ericsson/credm/service/data/certs
cp -f /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/data/certs/CredMServiceTS.jks  /ericsson/credm/service/data/certs

echo "dummy jks files copied"

chmod 777 /ericsson/credm/service/data/certs/*
chown jboss_user:jboss /ericsson/credm/service/data/certs/*

echo "chown of dummy jks files"

bash /ericsson/3pp/jboss/entry_point.sh &

sleep 30

while true; do
   bash /var/tmp/spsCertificateCheck.sh
   if [ $? -eq 0 ]; then
       exit 0
   fi

# check if deployment has failed
failed_undeployed_DEs=$(find /ericsson/3pp/jboss/standalone/deployments \( -type f -iname '*.failed' -o -iname '*.undeployed' \) -a ! -iname "dps-jpa-ear-runtime*")
failed_undeployed_DEs_COUNT=$(echo "$failed_undeployed_DEs" | wc -w)

   if [ "$failed_undeployed_DEs_COUNT" -gt 0 ]; then
       echo "jboss deployment failed. exiting"
       exit 126
   fi

   sleep 15
done

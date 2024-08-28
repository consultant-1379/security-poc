#!/bin/bash

echo "pki-manager RPM Postinstall"

if [ ! -e "/ericsson/pkimanager/data/xmlfiles/" ]; then
   mkdir -p /ericsson/pkimanager/data/xmlfiles/
fi 
if [ ! -e "/ericsson/sps/data/certs/" ]; then
   mkdir -p /ericsson/sps/data/certs/
   chmod 755 /ericsson/sps/data/certs/
   chown jboss_user:jboss /ericsson/sps/data/certs/
fi

cp /opt/ericsson/com.ericsson.oss.itpf.poc.security.pki-manager/pkimanagercredentialsrequest.xml /ericsson/pkimanager/data/xmlfiles

exit 0

#!/bin/bash

echo "pki-ra-scep RPM Postinstall"

#/opt/ericsson/ERICpkirascep
stringRunLevel=`grep '^id:' /etc/inittab`
runLevel=`sed "s/[^0-9]//g;s/^$/-1/;" <<< $stringRunLevel`
if [ ! -e "/ericsson/pkira/data/certs/" ]; then
   mkdir -p /ericsson/pkira/data/certs/
fi  
if [ ! -e "/ericsson/credm/data/xmlfiles/" ]; then
   mkdir -p /ericsson/credm/data/xmlfiles/
fi
if [ ! -e "/ericsson/pkira/data/crls/scep_crlstore/" ]; then
   mkdir -p /ericsson/pkira/data/crls/scep_crlstore/
fi
cp /opt/ericsson/ERICpkirascep/conf/scepra.xml /ericsson/credm/data/xmlfiles
chmod 400 /ericsson/credm/data/xmlfiles/scepra.xml
exit 0
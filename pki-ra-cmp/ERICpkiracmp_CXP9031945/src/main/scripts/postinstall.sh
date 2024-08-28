#!/bin/bash

echo "pki-ra-cmp RPM Postinstall"

#/opt/ericsson/ERICpkiracmp
stringRunLevel=`grep '^id:' /etc/inittab`
runLevel=`sed "s/[^0-9]//g;s/^$/-1/;" <<< $stringRunLevel`
if [ ! -e "/ericsson/pkira/data/certs/" ]; then
   mkdir -p /ericsson/pkira/data/certs/
fi
if [ ! -e "/ericsson/credm/data/xmlfiles/" ]; then
   mkdir -p /ericsson/credm/data/xmlfiles/
fi
if [ ! -e "/ericsson/pkira/data/crls/CMP_CRLStore/" ]; then
   mkdir -p /ericsson/pkira/data/crls/CMP_CRLStore/
fi
cp /opt/ericsson/ERICpkiracmp/conf/CMPRA.xml /ericsson/credm/data/xmlfiles
chmod 400 /ericsson/credm/data/xmlfiles/CMPRA.xml
exit 0   
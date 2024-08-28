#!/bin/bash

LOG_DIRECTORY=/var/log/enmcertificates/
LOG_NAME=enmCertificatesCrontab.log
XML_DIR=/ericsson/credm/data/xmlfiles


echo >> $LOG_DIRECTORY/$LOG_NAME


echo "`date +[%D-%T]`  Starting by cron credentialmanager.sh" >> $LOG_DIRECTORY/$LOG_NAME

/opt/ericsson/ERICcredentialmanagercli/bin/credentialmanager.sh -c -p  $XML_DIR &>> $LOG_DIRECTORY/$LOG_NAME

status=$?

if  [[ $status -eq 0 ]]; then
    echo " `date +[%D-%T]`  result : SUCCESS" >> $LOG_DIRECTORY/$LOG_NAME
elif  [[ $status -eq 100 ]]; then
    echo " `date +[%D-%T]`  result : Not allowed to run status=$status" >> $LOG_DIRECTORY/$LOG_NAME
else
    echo "`date +[%D-%T]`   result : FAILED status=$status" >> $LOG_DIRECTORY/$LOG_NAME
fi
echo >> $LOG_DIRECTORY/$LOG_NAME




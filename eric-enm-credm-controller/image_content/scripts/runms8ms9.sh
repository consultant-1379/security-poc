#!/bin/bash

# used env variables:
# RSYSLOG_FLAG 
# RSYSLOG_FILE
# CONTROLLER_NAME
# NAMESPACE
# SPS_APP_LABEL (inside python app)
# MS8MS9_JOB_NAME

echo "start CREDM CONTROLLER MS8MS9 JOB"

# mount global.properties
if [ ! -L /ericsson/tor/data/global.properties ]
then 
    if [ -f /gp/global.properties ]
    then
       echo "link to global properties"
       # make dir if not exist
       if [ ! -d "ericsson/tor/data" ]; then
	  mkdir -p ${gpdir}
       fi
       /bin/ln -s /gp/global.properties /ericsson/tor/data/global.properties; 
    fi
fi

# rsyslog
if [ "$RSYSLOG_FLAG" = true ] ; then
    cp /credm/resources/${RSYSLOG_FILE} /etc/rsyslog.d
    chmod 755 /etc/rsyslog.d/${RSYSLOG_FILE}
    chown root:root /etc/rsyslog.d/${RSYSLOG_FILE}
    echo "Starting rsyslog ..."
    /sbin/rsyslogd
fi


echo "run enabling job"
python3 /credm/src/ms8ms9job.py
res=$?
echo "terminated with result="$res
if [ $res -ne 0 ]; then
	echo "ERROR, return 1"
	exit 1
fi

echo "sleep some minutes...."
sleep 120
echo "....kill myself !!"
sleep 10

#controlledby=$(kubectl describe pod $HOSTNAME | grep "Controlled")
#echo $controlledby
#completename=$(echo $controlledby | awk -F":"  '{print $2}')
#echo $completename
#jobname=$(echo $completename | awk -F"/"  '{print $2}')
#echo $jobname

echo "stop job : "$MS8MS9_JOB_NAME
kubectl delete job ${CONTROLLER_NAME}-${MS8MS9_JOB_NAME} -n $NAMESPACE

exit 0







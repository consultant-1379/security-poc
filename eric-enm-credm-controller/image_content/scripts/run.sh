#!/bin/bash

# used env variables:
# RSYSLOG_FLAG 
# RSYSLOG_FILE
# CONTROLLER_NAME
# NAMESPACE
# SPS_APP_LABEL (inside python app)

echo "start CREDM CONTROLLER"

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

# patch to avoid httpd log (TODO)
#noHttpdLog="\ -Dorg.apache.commons.logging.Log=org.apache.commons.logging.impl.NoOpLog \\\\"
#sed -i "/credentialmanager.cli/i ${noHttpdLog} " /opt/ericsson/ERICcredentialmanagercli/conf/credentialmanagerconf.sh

echo "run server"
gunicorn wsgi:application --chdir=/credm/src/ --config=/credm/src/config.py


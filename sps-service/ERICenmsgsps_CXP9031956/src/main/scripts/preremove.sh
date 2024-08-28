#!/bin/bash

logger "Running Service Group RPM preremove"

sps_log (){
        msg=$1
        file=`hostname`
        echo "`date +[%D-%T]` $file $msg" &>> /ericsson/tor/data/credm/logs/spsservicegroup.log
}

sps_log "running RPM preremove"
/bin/rm -f /ericsson/tor/data/credm/hosts/$file
sps_log "removed $file..."

logger "SPS Service preremove  completed"

exit 0

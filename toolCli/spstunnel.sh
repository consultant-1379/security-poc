#!/bin/bash

start() {
    kubectl port-forward -n enm1605 $(kubectl get pods -n enm1605 |grep sps|awk '{print $1}') 11111:8080
}

status() {
    pid="$(ps -ef|grep 'kubectl port-forward'|grep 11111|awk '{print $2}')"

    if [ "$pid" == "" ]
    then
        echo "tunnel is down"
        return 0
    else
        echo "tunnel is up. pid $pid"
        return $pid
    fi
}

stop() {
    status
    ret=$?
    echo "$ret"
    if [ $ret != 0 ]
    then
        echo "check and kill it"
    fi
}

case "$1" in
    'start')
            start
            ;;
    'stop')
            stop
            ;;
    'restart')
            stop ; echo "Sleeping..."; sleep 1 ;
            start
            ;;
    'status')
            status
            ;;
    *)
            echo
            echo "Usage: $0 { start | stop | restart | status }"
            echo
            exit 1
            ;;
esac

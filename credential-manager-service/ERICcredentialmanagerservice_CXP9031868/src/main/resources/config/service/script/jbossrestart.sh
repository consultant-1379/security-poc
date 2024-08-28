#!/bin/bash
echo "jbossrestart BEGIN " >> /var/log/jbossrestart.log
for fd in $(ls /proc/$$/fd/); do
    if [[ $fd -gt 2 && $fd != 255 ]]; then
        echo "Closing $fd …" >> /var/log/jbossrestart.log
        eval "exec $fd>&-"
    fi
done
date >> /var/log/jbossrestart.log
nohup /etc/init.d/jboss restart 0<&- 1&>> /ericsson/3pp/jboss/standalone/log/console.log 2&>> /ericsson/3pp/jboss/standalone/log/console.log &

echo "jboss restart executed" >> /var/log/jbossrestart.log

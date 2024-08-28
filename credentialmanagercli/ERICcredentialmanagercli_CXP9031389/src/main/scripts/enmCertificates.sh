#!/bin/bash
# version 1
#
# enmCertificates     init script to manage service certificates
#
# chkconfig: 2345 90 35
# description: call the credentialmanager standalone service.
#

#
#       /etc/rc.d/init.d/<servicename>
#
#       <description of the *service*>
#       <any general comments about this init script>
#
# <tags -- see below for tag definitions.  *Every line* from the top
#  of the file to the end of the tags section must begin with a #
#  character.  After the tags section, there should be a blank line.
#  This keeps normal comments in the rest of the file from being
#  mistaken for tags, should they happen to fit the pattern.>

# Source function library.
. /etc/init.d/functions

#define any local shell functions used by the code that follows

XML_DIR=/ericsson/credm/data/xmlfiles
LOG_DIRECTORY=/var/log/enmcertificates/
LOG_NAME=enmCertificates.log
COMMAND=/opt/ericsson/ERICcredentialmanagercli/bin/credentialmanager.sh
STOP_CRON_FILE=/opt/ericsson/ERICcredentialmanagercli/conf/.stopCronVM
TIMEOUT_SECONDS=150


start() {
   touch $LOG_DIRECTORY/$LOG_NAME
   echo start `date` >> $LOG_DIRECTORY/$LOG_NAME

   if [[ -e $XML_DIR ]];
   then
        if [[ -e /tmp/stdout.out ]];
	then
		/bin/rm /tmp/stdout.out
	fi
	for FILE in $(find $XML_DIR -path $XML_DIR/template -prune -o -name '*.xml' \( -type f -or -type l \) -print | sort )
   	do
        	grep -q 'CertificateRequest.xsd' $FILE
        	if  [[ $? -eq 0 ]];
        	then
                	echo $FILE >> $LOG_DIRECTORY/$LOG_NAME
	
                	echo >> $LOG_DIRECTORY/$LOG_NAME
	
                	echo "CredentialManagerCli execution" >> $LOG_DIRECTORY/$LOG_NAME
	
                	echo >> $LOG_DIRECTORY/$LOG_NAME
	
        	else
                	echo >> $LOG_DIRECTORY/$LOG_NAME
	
                	echo "$FILE is not relative to a Certificate Request" >> $LOG_DIRECTORY/$LOG_NAME
	
                	echo >> $LOG_DIRECTORY/$LOG_NAME
        	fi
   	done


    #timeout to kill the java execution after a while (if it froze closing connections)
    timeout $TIMEOUT_SECONDS $COMMAND --install --path $XML_DIR &>> $LOG_DIRECTORY/$LOG_NAME
    status=$?
    if [ -f $STOP_CRON_FILE ] ; then
            echo  "INSTALL lock file removing, --check allowed from this point onward"  >> $LOG_DIRECTORY/$LOG_NAME
            rm -f $STOP_CRON_FILE
    fi

    if  [[ $status -eq 0 ]]; then
        echo "result : SUCCESS" >> $LOG_DIRECTORY/$LOG_NAME
    elif  [[ $status -eq 100 ]]; then
        echo "result : Not allowed to run status=$status"  >> $LOG_DIRECTORY/$LOG_NAME
    elif  [[ $status -eq 124 ]]; then
        echo "result : STOPPED by timeout"  >> $LOG_DIRECTORY/$LOG_NAME
    else
        echo "result : FAILED status=$status" >> $LOG_DIRECTORY/$LOG_NAME
    fi

   else
     echo "$XML_DIR doesn't exist" >> $LOG_DIRECTORY/$LOG_NAME
   fi

   echo end `date` >> $LOG_DIRECTORY/$LOG_NAME
}


default_answer() {
    exit 0
}

monitor() 
{
    echo "enmCertificates is running"
    exit 0
}


if [[ ( "$$1" == "true" ) && ( "$2" != "local" ) ]] ; then 
    echo "Running enmCertificates"
fi


case "$1" in
    start)
        start
        ;;
    restatus)
	start
	;;
    stop)
	default_answer
	;;
    status)
	monitor
	;;
    monitor)
	monitor
	;;



    *)

        echo "Usage: <servicename> {start|stop|status|restart|monitor}"
        exit 1
        ;;
esac
exit $?

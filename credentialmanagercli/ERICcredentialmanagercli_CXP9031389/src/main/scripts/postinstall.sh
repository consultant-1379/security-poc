#!/bin/sh

_SYSTEMCTL=/bin/systemctl
_PIDOF=/sbin/pidof

CLI_POSTINSTALL_LOG_FILE="/var/log/enmcertificates/CredManagerCliShellPostinstall.log"

COMMON_SHARED_FOLDER=/ericsson/tor/data/credm
XML_SHARED_DIR=$COMMON_SHARED_FOLDER/xmlfiles
HOST_LOG_FOLDER=$COMMON_SHARED_FOLDER/logs

PHASE=$1

cred_cli_log (){
    msg=$1
    echo "`date +[%D-%T]` $msg" &>> "$CLI_POSTINSTALL_LOG_FILE"
}


cred_cli_log "starting postinstall script ($PHASE)"

if [ ! -e "$XML_SHARED_DIR" ]; then
    mkdir -p $XML_SHARED_DIR
fi

hardening_files() {
# TORF-515189 and TORF-515501
    cred_cli_log "hardening_files"
   /bin/chmod 700 /opt/ericsson/ERICcredentialmanagercli/conf/credentialmanagerconf.sh
   /bin/chmod 600 /ericsson/credm/cli/data/CredM-CLI-CertRequest.xml
}

crontab_setup() {

    string_crontab=" * * * * root sh /opt/ericsson/ERICcredentialmanagercli/bin/credentialmanagercliCrontab.sh   > /dev/null 2>&1"

      # if last digit of ip is even then we set crontab entry in the 
      # range 0-14/30-44 
      # if instead last digit is odd then we set crontab entry in the 
      # range 15-29/45-59 

    RANGE=15
    lastipdigit=$(hostname --ip-address | awk -F "." ' { print $4 } ' )
    number=$RANDOM
    let "number %= $RANGE"
    let "result = $lastipdigit % 2"
    
      # odd cases...
    if [ $result  -eq 1 ]; then
	let " number += 15"
    fi
    
    let " numberoffset = $number + 30 "
      
    cred_cli_log "for crontab stuff number=$number and numberoffset $numberoffset $result(0 even 0-14/30-44, 1 odd 15-29/45-59)"
    cred_cli_log "$number,$numberoffset $string_crontab"
    
#      /bin/rm -f /etc/cron.d/credentialmanagercli
    sed -i "s/0/$number/" /etc/cron.d/credentialmanagercli
    sed -i "s/30/$numberoffset/" /etc/cron.d/credentialmanagercli
#      echo "$number,$numberoffset $string_crontab" > /etc/cron.d/credentialmanagercli

    /bin/chmod 644 /etc/cron.d/credentialmanagercli

}


cred_cli_log  "setup for installation and crontab setup"

touch /opt/ericsson/ERICcredentialmanagercli/conf/.stopCronVM

crontab_setup

cred_cli_log  "verify /etc/rc.local"
if ! grep -q enmCertificatesLocal.sh "/etc/rc.local"; then
    cred_cli_log "Adding enmCertificateLocal.sh start to rc\.local"
    if [ $($_PIDOF init) ]; then
        sed -i 's|touch \/var\/lock\/subsys\/local|touch \/var\/lock\/subsys\/local\necho \"Starting enmCertificatesLocal...\";\/opt\/ericsson\/ERICcredentialmanagercli\/bin\/enmCertificatesLocal.sh|' /etc/rc.d/rc.local
    elif [ $($_PIDOF systemd) ]; then
        # RHEL 7
        sed -i 's|touch \/var\/lock\/subsys\/local|touch \/var\/lock\/subsys\/local\necho \"Starting enmCertificatesLocal...\";\/opt\/ericsson\/ERICcredentialmanagercli\/bin\/enmCertificatesLocal.sh|' /etc/rc.d/rc.local
        # sed -i 's|touch \/var\/lock\/subsys\/local|touch \/var\/lock\/subsys\/local\necho \"Starting enmCertificatesLocal...\";\/bin\/systemctl start enmCertificates|' /etc/rc.d/rc.local
        cred_cli_log  "Enabling enmCertificates service on systemd"
        ${_SYSTEMCTL} enable enmCertificates.service
    else
        cred_cli_log "ERROR: Cannot find valid init for this system!"
    fi
fi

hardening_files

if [ ! -d "/tmp/cli_memory_report" ]; then
    mkdir -p "/tmp/cli_memory_report"
fi

if [ ! -d "$HOST_LOG_FOLDER" ]; then
    mkdir -p "$HOST_LOG_FOLDER"
fi
exit 0


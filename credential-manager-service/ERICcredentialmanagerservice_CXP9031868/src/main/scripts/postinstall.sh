#!/bin/sh

CRED_POSTINSTALL_LOG_FILE="/var/log/enmcertificates/CredManagerPostinstall.log"

cred_log (){
        msg=$1
        echo "`date +[%D-%T]` $msg" &>> "$CRED_POSTINSTALL_LOG_FILE"
}


if [ ! -d /var/log/enmcertificates ]; then
  mkdir -p /var/log/enmcertificates
fi

cred_log "starting postinstall script"


if [ ! -d /ericsson/credm/service/data ]; then
  mkdir -p /ericsson/credm/service/data
fi

if [ ! -d /ericsson/credm/service/data/extCA ]; then
  mkdir -p /ericsson/credm/service/data/extCA
fi

if [ ! -d /ericsson/credm/service/data/certs ]; then
  mkdir -p /ericsson/credm/service/data/certs
  chmod 755  /ericsson/credm/service/data/certs 
  chown jboss_user:jboss /ericsson/credm/service/data/certs
fi

if [ ! -d /ericsson/credm/service/data/enmInit ]; then
  mkdir -p /ericsson/credm/service/data/enmInit
fi

if [ ! -d /ericsson/credm/service/script ]; then
  mkdir -p /ericsson/credm/service/script
fi

if [ ! -d /ericsson/tor/data/credm/timers ]; then
  mkdir -p /ericsson/tor/data/credm/timers
fi

cred_log "Prepared all folders "

chmod ug+rwx,o-rwx /ericsson/credm/service
chown jboss_user:jboss /ericsson/credm/service

touch /ericsson/credm/service/jbossStartup.lock
chmod 640 /ericsson/credm/service/jbossStartup.lock
chown jboss_user:jboss /ericsson/credm/service/jbossStartup.lock

touch /ericsson/credm/service/removetojbossrestart.lock
chmod 640 /ericsson/credm/service/removetojbossrestart.lock
chown jboss_user:jboss /ericsson/credm/service/removetojbossrestart.lock

cp /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/script/jbossrestart.sh /ericsson/credm/service/script/
chmod 750 /ericsson/credm/service/script/jbossrestart.sh

cp /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/script/spsCertificateHC.sh /usr/lib/ocf/resource.d/
chmod 750 /usr/lib/ocf/resource.d/spsCertificateHC.sh

cp /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/data/config.properties /ericsson/credm/service/data/
chown jboss_user:jboss /ericsson/credm/service/data/config.properties
chmod 440 /ericsson/credm/service/data/config.properties

cp /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/data/extCA/*.pem /ericsson/credm/service/data/extCA
cp /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/data/extCA/*.crl /ericsson/credm/service/data/extCA
chown jboss_user:jboss -R /ericsson/credm/service/data/extCA
chmod -R ug+rw,o-rwx /ericsson/credm/service/data/extCA

cp -Rf /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/data/enmInit/credM  /ericsson/credm/service/data/enmInit/
chown jboss_user:jboss -R /ericsson/credm/service/data/enmInit 
chmod -R ug+rw,o-rwx /ericsson/credm/service/data/enmInit

cp /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/data/certs/CredMService.jks /ericsson/credm/service/data/certs/CredMService.jks
cp /opt/ericsson/com.ericsson.oss.itpf.security.credential-manager-service/config/service/data/certs/CredMServiceTS.jks /ericsson/credm/service/data/certs/CredMServiceTS.jks
chown jboss_user:jboss /ericsson/credm/service/data/certs/*.jks
chmod 440 /ericsson/credm/service/data/certs/*.jks

cred_log "Done "

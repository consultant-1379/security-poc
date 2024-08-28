#!/bin/bash
LOCK_FILE="/ericsson/credm/service/jbossStartup.lock"
LOCK_JBOSS_RESTART="/ericsson/credm/service/removetojbossrestart.lock"
TOUCH=/bin/touch
CHMOD=/bin/chmod
CHOWN=/bin/chown

if [[ ! -e  $LOCK_JBOSS_RESTART ]] ; then
  logger -t CREDENTIAL_MGR_SERVICE  -p user.notice "Invoking JBOSS restart to reload credentials"
  /ericsson/credm/service/script/jbossrestart.sh
  ${TOUCH} $LOCK_JBOSS_RESTART
  ${CHMOD} 644 $LOCK_JBOSS_RESTART
  ${CHOWN} jboss_user:jboss $LOCK_JBOSS_RESTART
fi

if [[ -e  $LOCK_FILE ]] ; then
  exit 1
else
  exit 0 
fi


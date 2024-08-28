#===============================================================================
#
#          FILE: credentialmanagerconf.sh
# 
#===============================================================================



#log folder definitions
LOG_DIRECTORY=/var/log/enmcertificates
JAVA_CLI_LOG_DIR=/var/log/credentialmanager

# log files
CRED_LOG_FILE=$LOG_DIRECTORY/CredManagerCliShell.log
DATE_CLI_FILE=$LOG_DIRECTORY/warning_date.txt

CRONTAB_LOCK_FILE=$LOG_DIRECTORY/crontab_lock_file

# shared folders definitions
COMMON_SHARED_FOLDER=/ericsson/tor/data/credm
HOSTS_INFO_DIR=$COMMON_SHARED_FOLDER/hosts
LOG_HOST_DIR=$COMMON_SHARED_FOLDER/logs
XML_SHARED_DIR=$COMMON_SHARED_FOLDER/xmlfiles

CLI_GEN_CONF_FILE=$COMMON_SHARED_FOLDER/conf/clicopyxml


XML_DIR=/ericsson/credm/data/xmlfiles

API_FILE_VERSION=$CLI_CONF_DIR/version.properties


# definitions of files where fetch credmcli behaviuor
CRED_BEHAVIOUR_CONFFILE=/etc/credm/conf.d/credentialManagerCliConfigurator
# file name different due the fact is common also to cred on SPS side
CRED_BEH_CONFFILE_OVERWRITE="$COMMON_SHARED_FOLDER/conf/credentialManagerConfigurator.properties"

# configuration files for rest/jboss definition
REST_CONFIGFILE_OUT=$CLI_CONF_DIR/config.properties
REST_CONFIGFILE_IN=$CLI_CONF_DIR/config.properties_INITIAL

SECURE_JBOSS_CONFIGFILE_OUT=$CLI_CONF_DIR/jboss-ejb-client.properties
SECURE_JBOSS_CONFIGFILE_IN=$CLI_CONF_DIR/jboss-ejb-client.properties_INITIAL


CREDCLI_CERTS_DIR=/ericsson/credm/cli
CREDCLI_INSTALL_DIR=/opt/ericsson/ERICcredentialmanagercli

STATE_FILE=$CREDCLI_INSTALL_DIR/.state
STOP_CRON_FILE=$CREDCLI_INSTALL_DIR/conf/.stopCronVM

WARNING_CHECK_VALUE="-checkWarningDate"

DEBUG=0
INFO=1
WARN=2
ERROR=3

DEFAULT_LOG_LEVEL=$INFO
LOG_LEVEL_INFO_STRINGS=( "DEBUG" "INFO " "WARN " "ERROR" )

API_COMPATIBLE_CHECK="true"
SAVE_DEFAULT_FILES="false"

EXIT_OK=0
EXIT_JAVA_NOT_ALLOWED_TO_RUN=100
EXIT_EMPTY_FOLDER=105
EXIT_NO_API_AVAILABLE=110
EXIT_INSTALL_RUNNING=115

JBOSS_SECURE_HOST="remote.connection.HOST.host = IP
remote.connection.HOST.port = 4447
remote.connection.HOST.connect.options.org.xnio.Options.SASL_POLICY_NOANONYMOUS=false
remote.connection.HOST.connect.options.org.xnio.Options.SSL_STARTTLS=true"

# number of days for files saved
OLD_FILES_MAINTAIN=45


# logs files to be updated in case of taf running

LOG4_CONFFILE=$CLI_CONF_DIR/log4j2.properties
#LOG4_ERROR_CONFFILE=$CLI_CONF_DIR/log4j_error.properties


# xms memory allocated at start-up, xmx max memory allocated for heap, 
# define usage of concurrent collector with  -verbose:gc

MEMORY_DEFAULT_HOSTS_NUMBER=5
MIN_HOSTS_NUMBER_TO_SCALE=9
#MEMORY_PARAMETERS="-Xms75M -Xmx150M -Xss10M"
MEMORY_DEFAULT_PARAMETERS="-Xms75M -Xmx150M  "
MEMORY_PARAMETERS="-Xms75M -XmxnnnM  "
#the maximum value will be evaluated dinamically
MEMORY_BASE_VALUE=120
MEMORY_STEP_VALUE=15
#MEMORY_PARAMETERS=" "


# TORF-586137 : avoid password on command line
export KEYSTOREPASSWORD="credmKS"
export TRUSTSTOREPASSWORD="credmTS"
JAVA_PARAMETERS="-cp $CREDCLI_INSTALL_DIR/*:$CREDCLI_INSTALL_DIR/bin/*:$CREDCLI_INSTALL_DIR/conf/*:\
$CREDCLI_INSTALL_DIR/lib/*:. -Djboss.ejb.client.properties.file.path=$CREDCLI_INSTALL_DIR/conf/jboss-ejb-client.properties\
 -Djavax.net.ssl.keyStore=$CREDCLI_CERTS_DIR/data/certs/credmApiKS.JKS \
 -Djavax.net.ssl.trustStore=$CREDCLI_CERTS_DIR/data/certs/credmApiTS.JKS \
 -Dlog4j2.configurationFile=file:${LOG4_CONFFILE}
 com.ericsson.oss.itpf.security.credentialmanager.cli.CLI" 


#timeout value of SLS 
STARTUP_WAIT=30

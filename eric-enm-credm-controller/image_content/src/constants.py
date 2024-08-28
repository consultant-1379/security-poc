#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  CREDM CONSTANTS              #
#                               #
#################################

# constant.py

from os import environ as env
import logging

JAVA_MOCK_FLAG = str(env.get("JAVA_MOCK_FLAG", "false")) == "true"
LOG_DEBUG_FLAG = str(env.get("LOG_DEBUG_FLAG", "false")) == "true"
LOG_FILE_DEBUG_FLAG = str(env.get("LOG_FILE_DEBUG_FLAG", "false")) == "true"
LOG_LEVEL = logging.DEBUG
LOG_LEVEL_ERROR = "ERROR"
LOG_LEVEL_WARNING = "WARNING"
LOG_LEVEL_DEBUG = "DEBUG"
LOG_LEVEL_INFO = "INFO"
LOG_FILENAME = "/var/log/credmcontroller/credmcontroller.log"
LOG_ROTATE_SIZE = 52428800      # 50 Mb
LOG_ROTATE_NUM = 10

CERT_REQ_OPERATION = "CERT_REQUEST"
CRON_CHECK_OPERATION = "CRON_CHECK"
# TODO need to differentiate for ROLLBACK ?

NAMESPACE = str(env.get("NAMESPACE", "default"))
PORT = int(env.get("REST_PORT", 5001))
CONTROLLER_NAME = str(env.get("CONTROLLER_NAME", "none"))

CERTREQ_STATE = {
    'EMPTY': 'empty',
    'READY': 'ready',
    'UPDATING': 'updating',
    'UPDATED': 'updated'
}

CRED_DATA_CERT_FOLDER: str = "/ericsson/credm/data/certs/"
CRED_DATA_XMLFILES_FOLDER = "/ericsson/credm/data/xmlfiles/"
CRED_DATA_PRESTART_SCRIPT_FOLDER = "/ericsson/credm/cli/script/pre-start/"
CRED_DATA_PRESTART_SCRIPT_ROTATE_NUM = 10

CRED_CLI_XML_FILE_PATH = "/ericsson/credm/cli/data/CredM-CLI-CertRequest.xml"

SPS_APP_LABEL = str(env.get("SPS_APP_NAME", "sps"))
SPS_POD_LABEL_CREDM_API_VERSION = 'credm.api.version'
SPS_POD_LABEL_DEPLOYMENT = "deploymentName"
SPS_FILES_FOLDER = "/ericsson/tor/data/credm/hosts/"
SPS_WAIT_STARTUP = 45
CREDM_CONTROLLER_API_VERSION_FILE = "/opt/ericsson/ERICcredentialmanagercli/conf/version.properties"
CREDM_CONTROLLER_STATE_FILE = "/opt/ericsson/ERICcredentialmanagercli/.state"

XML_KEYSTORE = 'keystore'
XML_TRUSTSTORE = 'truststore'
XML_CRLSTORE = 'crlstore'
XML_STORELOCATION = 'storelocation'
XML_STOREFOLDER = 'storefolder'
XML_KEYFILELOCATION = 'keyfilelocation'
XML_CERTIFICATELOCATION = 'certificatefilelocation'

# constants for certReq secret
SECRET_LABEL_SERVICENAME = "serviceName"
SECRET_LABEL_CERTREQUEST = "certRequest"
SECRET_CERTREQNAME = "certReqName"
SECRET_CERTREQDATA = "certReqData"
SECRET_CERTREQSTATE = "certReqState"
SECRET_CERTREQMD5 = "certReqMD5"
SECRET_CERTREQSCRIPT = "certReqScript"

# constants for TLS secret
TLSSTORE_TYPE = {
    'FILE': 'file',
    'FOLDER': 'folder',
    'CRLFILE': 'CRLfile',
    'CRLFOLDER': 'CRLfolder',
    'POSTSCRIPT': 'postscript'
}

SECRET_LABEL_CERTREQNAME = "certReqName"
SECRET_TLSSTORELOCATION = "tlsStoreLocation"
SECRET_TLSSTORETYPE = "tlsStoreType"
SECRET_TLSSTOREDATA = "tlsStoreData"
SECRET_NONESTATE = "none"
SECRET_EMPTYDATA = "empty"

DEPLOYMENT_RESTARTCNT = "restartcnt"

RESULT_FROM_API_OK = "OK"
RESULT_FROM_API_NOT_OK = "NOT_OK"
# note: NOT_OK is used as string also in runjob.sh
RESULT_FROM_API_NEGATIVE_TAG = "NOT"

# extimate time to perform credentialamangercli 
PROCESSING_TIMEOUT = 30

# CONSTANTS FOR ERICcredentialmanagercli
ERICREDENTIALMANAGERSHELL_LOG_DIR: str = "/var/log/enmcertificates/"
ERICREDENTIALMANAGERSHELL_LOG_FILE: str = "CredManagerCliShell.log"
ERICREDENTIALMANAGERCLI_LOG_DIR: str = "/var/log/credentialmanager/"
ERICREDENTIALMANAGERCLI_LOG_FILE: str = "stdout.out"
ERICREDENTIALMANAGERCLI_BIN_DIR: str = "/opt/ericsson/ERICcredentialmanagercli/bin/"
ERICREDENTIALMANAGERCLI_COMMAND = "credentialmanager.sh"


#
# constants for CREDM STATE SECRET (MS8/MS9 feature)
#
CONTROLLER_STATE_SECRET_NAME = "eric-enm-credm-controller-state"
CONTROLLER_STATE_SECRET_CREDMSTATE_FIELD = "credmEnableState"
CONTROLLER_STATE_SECRET_CRONSTATE_FIELD =  "cronWorkingState"

#  eric-enm-credm-controller-state status
CREDMENABLE_STATE = {
    'ENABLED': 'enabled',
    'DISABLED': 'disabled',
    'ENABLING': 'enabling'
}
CRONENABLE_STATE = {
    'IDLE': 'idle',
    'WORKING': 'working'
}

# credmenable states accepting cronJobState command
VALID_STATE_FOR_CRONENABLE = [CREDMENABLE_STATE['ENABLED']]

# global state (depending on CREDMENABLE_STATE and CRONENABLE_STATE)
ENABLE_STATE = {
    'ENABLED': 'enabled',
    'DISABLING': 'disabling',
    'DISABLED': 'disabled',
    'ENABLING': 'enabling'
}

# actions for monitoring command
ENABLE_ACTION = {
    'ENABLE': 'enable',
    'DISABLE': 'disable',
    'RESET': 'reset'
}

# action for cronJobState command
CRONJOB_ACTION = {
    'START': 'start',
    'STOP': 'stop'
}

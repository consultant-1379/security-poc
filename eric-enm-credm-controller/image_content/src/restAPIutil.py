#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  REST SERVER  UTILITIES       #
#                               #
#################################

import os
import constants
import common
import globalData
import k8sApiInterface
import javaMock


###########################################
# clearData
#
# descr: clear common data and remove files
#
# in: none
# out:  boolean
###########################################
def clearData():

    common.log(constants.LOG_LEVEL_DEBUG, "clearData " )

    # remove HOSTS files
    # TODO these files are in tor/data
    common.removePath(constants.SPS_FILES_FOLDER)
    common.createFolder(constants.SPS_FILES_FOLDER)
        
    # remove old service xml files in /ericsson/credm/data/xmlfiles
    # create empty dir /ericsson/credm/data/xmlfiles
    common.removePath(constants.CRED_DATA_XMLFILES_FOLDER)
    common.createFolder(constants.CRED_DATA_XMLFILES_FOLDER)
    common.removePath(constants.CRED_DATA_PRESTART_SCRIPT_FOLDER)
    common.createFolder(constants.CRED_DATA_PRESTART_SCRIPT_FOLDER)

    # clear globalData
    for item in globalData.tlsItemsList:
        if item.tlsType == constants.TLSSTORE_TYPE['FILE'] or item.tlsType == constants.TLSSTORE_TYPE['FOLDER']:
            common.removePath(item.getTlsLocation())
        if item.tlsType == constants.TLSSTORE_TYPE['CRLFILE'] or item.tlsType == constants.TLSSTORE_TYPE['CRLFOLDER']:
            common.removePath(item.getTlsLocation())

    globalData.initGlobalData()
    #
    return True 


###########################################
#
# load SPS POD
#
# in: none
# out: podList
###########################################
def loadSpsPods():

    # implementation to retrieve all SPS POD 

    # use this label to retrieve only the SPS with the right api version
    # label_selector = constants.SPS_POD_LABEL_CREDM_API_VERSION
 
    common.log(constants.LOG_LEVEL_DEBUG, "loadSpsPods : value used for label = %s " % constants.SPS_APP_LABEL)
    label_selector = "app in ("+constants.SPS_APP_LABEL+")"
    retList = k8sApiInterface.readPodsWithLabel(constants.NAMESPACE, label_selector)

    return retList


###########################################
# runCredentialmanagerCli
#
# descr: execute the script that run the java code
#
# in: serviceName
# out:  return code
###########################################
def runCredentialmanagerCli(serviceName):

    # logFile is written by shell script
    # logFile2 is written by java execution
    logFile = constants.ERICREDENTIALMANAGERSHELL_LOG_DIR + constants.ERICREDENTIALMANAGERSHELL_LOG_FILE
    logFile2 = constants.ERICREDENTIALMANAGERCLI_LOG_DIR + constants.ERICREDENTIALMANAGERCLI_LOG_FILE

    # pre-start scripts phase

    # execute pre start script
    common.log(constants.LOG_LEVEL_INFO, "runCredentialmanagerCli: run pre-start scripts")
    message = "["+common.timeNow()+"]  INFO  "+"START prestart script for "+serviceName
    common.appendTextFile(logFile, message)
    #
    resScript = common.executeScriptsOnFolder(constants.CRED_DATA_PRESTART_SCRIPT_FOLDER, logFile)
    #
    message = "["+common.timeNow()+"]  INFO  "+"END prestart script for "+serviceName
    common.appendTextFile(logFile, message)

    # check result of script execution
    if not resScript:
        common.log(constants.LOG_LEVEL_WARNING, "runCredentialmanagerCli: pre-start scripts failed, skip credentialmangercli java")
        return 1
        
    # log start of execution
    message = "["+common.timeNow()+"]  INFO  "+"START "+globalData.typeOfOperation+" for "+serviceName
    common.appendTextFile(logFile, message)
    common.appendTextFile(logFile2, message)

    ret = 0
    #
    # execute credentialamangercli java
    #
    if not constants.JAVA_MOCK_FLAG:

        common.log(constants.LOG_LEVEL_INFO, "runCredentialmanagerCli: start credentialmangercli java")

        cmd = ''
        if globalData.typeOfOperation == constants.CERT_REQ_OPERATION:
            cmd = constants.ERICREDENTIALMANAGERCLI_BIN_DIR + constants.ERICREDENTIALMANAGERCLI_COMMAND + \
                " -i -p " + constants.CRED_DATA_XMLFILES_FOLDER 
        if globalData.typeOfOperation == constants.CRON_CHECK_OPERATION:
            cmd = constants.ERICREDENTIALMANAGERCLI_BIN_DIR + constants.ERICREDENTIALMANAGERCLI_COMMAND + \
                " -c -p " + constants.CRED_DATA_XMLFILES_FOLDER

        common.log(constants.LOG_LEVEL_DEBUG, "runCredentialmanagerCli; start CREDENTIALMANAGERCLI execution:"+cmd)
        ret = common.executeCommand(cmd, logFile)

        # credentialmanager has a return code to be analyzed. It returns 0 if all was fine.
        common.log(constants.LOG_LEVEL_DEBUG,
                   "runCredentialmanagerCli; code returned by credentialmanager.sh is %s " % ret)

    else:
        #
        # ONLY FOR DEBUG: simulate a run of credentialamangercli java
        #
        if globalData.typeOfOperation == constants.CERT_REQ_OPERATION:
            javaMock.mockInitalInstall()
        elif globalData.typeOfOperation == constants.CRON_CHECK_OPERATION:
            javaMock.mockPeriodicCheck()

    # log end of execution
    message = "["+common.timeNow()+"]  INFO  "+"END "+globalData.typeOfOperation+" for "+serviceName
    common.appendTextFile(logFile, message)
    common.appendTextFile(logFile2, message)

    return ret


###########################################
#                                         #
#   COMMON UTLITIES                       #
#                                         #
###########################################


###########################################
#
# retrieve and calculate md5 form xml file
#
# in: certReqSecretItem (secret)
# out: saved_md5, calculated_md5
###########################################
def readAndCalculateXmlMd5(certReqSecretItem):

    common.log(constants.LOG_LEVEL_DEBUG, \
        f"readAndCalculateXmlMd5; secret name {certReqSecretItem.metadata.name}")

    certreq_data = certReqSecretItem.data[constants.SECRET_CERTREQDATA]
    certreq_data_string = common.decodeString(certreq_data)

    certreq_md5 = certReqSecretItem.data[constants.SECRET_CERTREQMD5]
    certreq_md5_string = common.decodeString(certreq_md5)

    saved_md5 = certreq_md5_string
    calc_md5 =  common.calculateStringMD5(certreq_data_string)

    common.log(constants.LOG_LEVEL_DEBUG, \
        f"readAndCalculateXmlMd5; read XML MD5 {saved_md5} - calculated  XML MD5 {calc_md5}")

    return (saved_md5, calc_md5)

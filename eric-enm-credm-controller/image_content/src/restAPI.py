
#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  REST SERVER                  #
#                               #
#################################

#import json
import os
import constants
import common
import globalData
import restAPIutil
import restAPIsecretUtil
import restAPIms8ms9
import k8sApiInterface
import preprocXML
import xmlParser
import javaMock


# global variables definition
#service_name
#tagOperationForMessages
#forceRestartForUpgrade

#print("JAVA_MOCK_FLAG: %r" % constants.JAVA_MOCK_FLAG)
#print("LOG_DEBUG_FLAG: %r" %constants.LOG_DEBUG_FLAG)


###########################################
# restList
#
# descr: list of exported REST
#
# in: none
# out:  json list of REST
###########################################
def restList():
    str_list = []
    str_list.append("CredM Controller Alive \n")
    str_list.append("--- \n")
    str_list.append("REST API for PRODUCTION: \n")
    str_list.append("   /certrequest/<string:service_name>    [GET] \n")
    str_list.append("   /certrequest/<string:service_name>/<string:date_in_seconds>/<string:timeout>    [GET] \n")
#    str_list.append("   /upgrade/<string:service_name>    [GET] \n")
#    str_list.append("   /rollback/<string:service_name>    [GET] \n")
    str_list.append("   /periodicCheck/<string:service_name>   [GET] \n")
    str_list.append("   /getServicesListWithCertificates       [GET] \n")   
    str_list.append("--- \n")
    return ''.join(str_list)


###########################################
# certrequest
#
# descr: perform a initial installation or an upgrade for the given service
#
# in: serviceName (string)
#     date_in_seconds (string)
#     timeout (string)
# out:  result (string)
###########################################
def certrequest(serviceName, date_in_seconds, timeout):
    common.log(constants.LOG_LEVEL_INFO, f"start certrequest: serviceName {serviceName}, date_in_seconds {date_in_seconds}, timeout {timeout} ")

    # set the type of operation started
    globalData.typeOfOperation = constants.CERT_REQ_OPERATION
    # note CERTREQ_OPERATION is both initial install and upgrade
    # TODO need to differentiate for ROLLBACK ?
    globalData.tagOperationForMessages = "certReq."
    globalData.forceRestartForUpgrade = False

    ret = common.evaluateCertRequestAge(date_in_seconds, timeout)
    if ret == False:
        common.log(constants.LOG_LEVEL_WARNING, f"certrequest: discarded too late request from servce = {serviceName}")
        return {globalData.tagOperationForMessages + ' is NOT_OK for service': serviceName}

    return __prepareAndRunCredentialManagerCli(serviceName)


###########################################
# periodicCheck
#
# descr: perform the periodic check for the given service
#
# # in: serviceName (string)
# out:  result (string)
###########################################
def periodicCheck(serviceName):
    common.log(constants.LOG_LEVEL_INFO, f"start periodicCheck:  serviceName {serviceName}")

    # set the type of operation started
    globalData.typeOfOperation = constants.CRON_CHECK_OPERATION
    globalData.tagOperationForMessages = "check."
    globalData.forceRestartForUpgrade = False  

    return __prepareAndRunCredentialManagerCli(serviceName)


###########################################
# servicesList
#
# descr: check for services that need for certificates
#
# in:  none
# out:  result (json): list of names of services that need for certificates
###########################################
def servicesList(forceFlag):

    common.log(constants.LOG_LEVEL_INFO, "start servicesList ")

    #get the names list of services that need for certificates
    serviceNameList = []

    if forceFlag:
        common.log(constants.LOG_LEVEL_DEBUG, "servicesList - force flag received: ")
    else:
        # check if controller state in valid state to manage a cron job
        credmStateValue, cronStateValue, enableStateValue = restAPIms8ms9.getMonitoringState(allFlag=True)
        if credmStateValue in constants.VALID_STATE_FOR_CRONENABLE:
            forceFlag = True
        else:
            common.log(constants.LOG_LEVEL_INFO, "servicesList - no list returned because controller not enabled ")

    if forceFlag:
        # read the list of 'cert-request' secrets with label certRequest: "true"
        retSecretsList = restAPIsecretUtil.loadAllCertReqSecrets()
        for item in retSecretsList.items:
            serviceName = item.metadata.labels[constants.SECRET_LABEL_SERVICENAME]
            if serviceName not in serviceNameList:
                common.log(constants.LOG_LEVEL_DEBUG, "servicesList - service found : " + serviceName)
                serviceNameList.append(serviceName)

    #ONLY FOR DEBUG
    #serviceNameList.append(constants.RESULT_FROM_API_NOT_OK)
    return serviceNameList


###########################################
#  RUN CREDENTIALMANAGERCLI               #
###########################################


###########################################
# __prepareAndRunCredentialManagerCli
#
# descr: perform a complete run of credential manager for the given service
# main steps:
#  - check SPS and prepare host files with their IP
#  - prepare certificates for itself
#  - retrieve service xml files and secrets 
#  - run credentialamangercli java (with SPS communication)
#  - update secrets
#  - clear data 
#
# in: serviceName (string)
# out:  result (string)
###########################################
def __prepareAndRunCredentialManagerCli(serviceName):

    common.log(constants.LOG_LEVEL_INFO, "run CredentialManagerCli {} for service: {}".format(globalData.typeOfOperation, serviceName))

    # global data
    global service_name
    service_name = serviceName

    # initial clear:
    # remove old hosts files for sps pods
    # remove old service certs files 
    # clear global data
    restAPIutil.clearData()
      
    # get SPS pods and write hosts file
    __getSpsPodAndwriteHostFiles()
    
    #
    #  prepare data for credentialmanagercli java
    #  - preprocessing/parsing of file CredM-CLI-CertRequest.xml 
    #  - read cli certs secrets and copy on file system (if not already present)
    #  - calculate md5 for keyStore and trustStore of cli 
    ret = __prepareDataForCli()
    if ret == True:
        common.log(constants.LOG_LEVEL_DEBUG, "__prepareAndRunCredentialManagerCli : __prepareDataForCli returned OK")
    else:
        common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli : __prepareDataForCli returned NOT OK")

        # reset data for cli tls secrets if it is necessary
        ret = __resetDataForCliTlsSecrets()
        if ret == False:
            common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli : __resetDataForCliTlsSecrets returned NOT OK")

        # TODO Is it necessary to do something for service secrets?

        # return from rest API with string OK/NOT_OK
        if constants.RESULT_FROM_API_NEGATIVE_TAG in globalData.globalResultToReturnFromApi:
            return {globalData.tagOperationForMessages + ' is NOT_OK for service': serviceName}
        else:
            return {globalData.tagOperationForMessages + ' is OK for service': serviceName}
        
    # get certReq secrets for <serviceName> and save data
    ret = __getCertReqSecretsAndFillGlobalData()
    if ret == True:
        common.log(constants.LOG_LEVEL_DEBUG, "__prepareAndRunCredentialManagerCli : __getCertReqSecretsAndFillGlobalData returned OK")
    else:
        common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli : __getCertReqSecretsAndFillGlobalData returned NOT OK")

        # reset data for cli tls secrets if it is necessary
        ret = __resetDataForCliTlsSecrets()
        if ret == False:
            common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli : __resetDataForCliTlsSecrets returned NOT OK")
        
        # TODO Is it necessary to do something for service secrets?

        # return from rest API with string OK/NOT_OK
        if constants.RESULT_FROM_API_NEGATIVE_TAG in globalData.globalResultToReturnFromApi:
            return {globalData.tagOperationForMessages + ' is NOT_OK for service': serviceName}
        else:
            return {globalData.tagOperationForMessages + ' is OK for service': serviceName}
    
    # 
    # execute credentialamangercli java
    #
    common.log(constants.LOG_LEVEL_INFO, "__prepareAndRunCredentialManagerCli: ready for credentialamanagercli")
    res = restAPIutil.runCredentialmanagerCli(serviceName)
    if res != 0:
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli: credentialmanagercli java FAILED")

        # reset data for cli tls secrets if it is necessary
        ret = __resetDataForCliTlsSecrets()
        if ret == False:
            common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli : __resetDataForCliTlsSecrets returned NOT OK")
            
        # TODO Is it necessary to do something for service secrets?

        # return from rest API with string NOT_OK
        return {globalData.tagOperationForMessages + ' is NOT_OK for service': serviceName}

    # 
    # final part: save and close
    #

    # check if cli certificates files changed and update cli tls secret (check with md5 if cli certs are changed)
    ret = __updateDataForCli()
    if ret == True:
        common.log(constants.LOG_LEVEL_INFO, "__prepareAndRunCredentialManagerCli : __updateDataForCli returned OK")
    else:
        common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli : __updateDataForCli returned NOT OK")

        # reset data for cli tls secrets if it is necessary
        ret = __resetDataForCliTlsSecrets()
        if ret == False:
            common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli : __resetDataForCliTlsSecrets returned NOT OK")
        # Is it necessary to do something for service secrets?
        # return from rest API with string OK/NOT_OK
        if constants.RESULT_FROM_API_NEGATIVE_TAG in globalData.globalResultToReturnFromApi:
            return {globalData.tagOperationForMessages + ' is NOT_OK for service': serviceName}
        else:
            return {globalData.tagOperationForMessages + ' is OK for service': serviceName}
    
    # update tls and cert. req. secrets for the service
    ret = __updateDataForService()
    if ret == True:
        common.log(constants.LOG_LEVEL_INFO, "__prepareAndRunCredentialManagerCli : __updateDataForService returned OK")
    else:
        common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli : __updateDataForService returned NOT OK")
        
        # TODO Is it necessary to do something for service secrets?

        # return from rest API with string OK/NOT_OK
        if constants.RESULT_FROM_API_NEGATIVE_TAG in globalData.globalResultToReturnFromApi:
            return {globalData.tagOperationForMessages + ' is NOT_OK for service': serviceName}
        else:
            return {globalData.tagOperationForMessages + ' is OK for service': serviceName}

    # restart of service is invoked for the following reasons:
    # - .state files is set by enmcertificates.sh only in case of CRON_CHECK_OPERATION 
    # - forceRestartForUpgrade flag in case of UPGRADE (included in CERT_REQ_OPERATION)
    if globalData.typeOfOperation == constants.CRON_CHECK_OPERATION or globalData.typeOfOperation == constants.CERT_REQ_OPERATION:

        # check for necessity to restart the service
        if common.doesFileExist(constants.CREDM_CONTROLLER_STATE_FILE) or globalData.forceRestartForUpgrade:
        
            common.log(constants.LOG_LEVEL_INFO, "__prepareAndRunCredentialManagerCli: need to restart the service %s" % service_name)
        
            # remove file to avoid further restarts
            common.removePath(constants.CREDM_CONTROLLER_STATE_FILE)
        
            # restart the service
            ret = k8sApiInterface.restartService(service_name, constants.NAMESPACE)
            if ret == False:
                common.log(constants.LOG_LEVEL_WARNING, "__prepareAndRunCredentialManagerCli: unable to restart the service %s" % service_name) 
                if constants.RESULT_FROM_API_NEGATIVE_TAG in globalData.globalResultToReturnFromApi:
                    return {globalData.tagOperationForMessages + ' is NOT_OK for service': serviceName}
                else:
                    return {globalData.tagOperationForMessages + ' is OK for service': serviceName}
        else:
            common.log(constants.LOG_LEVEL_INFO, "__prepareAndRunCredentialManagerCli: NO need to restart the service %s" % service_name)

    return {globalData.tagOperationForMessages + ' is OK for service': serviceName}

# end of __prepareAndRunCredentialManagerCli


#########################################################
#
#   COMMON PARTS
#
########################################################


###########################################
# getSpsPodAndwriteHostFiles
#
# descr: retrive SPS pods and write HOST files
#
# in: none
# out:  boolean
###########################################
def __getSpsPodAndwriteHostFiles():

    common.log(constants.LOG_LEVEL_DEBUG, "__getSpsPodAndwriteHostFiles: finding PODs with the label: " + constants.SPS_POD_LABEL_CREDM_API_VERSION)

    # get pods with label
    retList = restAPIutil.loadSpsPods()

    # find data for SPS host files
    spsHostsList = []
    for item in retList.items:
        # TODO
        # TEMP NO API VERSION
        apiVersion = "1.1.2"
        if constants.SPS_POD_LABEL_CREDM_API_VERSION in item.metadata.labels: 
            apiVersion = item.metadata.labels[constants.SPS_POD_LABEL_CREDM_API_VERSION]
        # END TEMP
        itemStr = 'NAME: {} IP: {} API VERSION: {}'.format(item.metadata.name, item.status.pod_ip, apiVersion)
        common.log(constants.LOG_LEVEL_DEBUG, "SPS host:" + itemStr)
        spsHostsList.append((item.metadata.name, item.status.pod_ip, apiVersion))

    # write HOSTS files
    common.writeSPShostFiles(spsHostsList)

    return True


###########################################
# __getCertReqSecretsAndFillGlobalData
#
# for each cerReq secret of the service:
#   if tls certs not already done for the cerReq secret:
#       - preprocess xml, write xml file on file system
#       - parse xml to prepare globalData (fill tlsType, tlsLocation
#         and certReqSecretName fields)
#       - create folders for service tls certs that will be generated by cli
# in: none
# out:  boolean
###########################################
def __getCertReqSecretsAndFillGlobalData():
    
    common.log(constants.LOG_LEVEL_DEBUG, "finding CertReq Secrets with the label: " + service_name)

    # retrieve secret with label
    retList = restAPIsecretUtil.loadCertReqSecretsForService(service_name)

    # check if any secret found
    if len(retList.items) == 0:
        common.log(constants.LOG_LEVEL_WARNING, "__getCertReqSecretsAndFillGlobalData : NOT FOUND certRequest secrets for service = %s" %service_name)
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return False

    # check if the tls secrets for service are all already filled
    # i.e certReqState field = ready
    certSecretsTotalNum = 0
    certSecretsInReadyStateNum = 0
     
    # for each secret
    for secretItem in retList.items:

        secret_name = secretItem.metadata.name
        certreq_xmlname = secretItem.data[constants.SECRET_CERTREQNAME]
        certreq_data = secretItem.data[constants.SECRET_CERTREQDATA]
        certreq_state = secretItem.data[constants.SECRET_CERTREQSTATE]
        
        # decode string
        certreq_xmlname_string = common.decodeString(certreq_xmlname)
        certreq_data_string = common.decodeString(certreq_data)
        certreq_state_string = common.decodeString(certreq_state)

        # TODO here the point where to differentiate for ROLLBACK, if need

        # upgrade operation (CERT_REQ_OPERATION): check if XML inside certReqSecret is changed
        # in that case secrets contents are reset and a restart is forced
        if globalData.typeOfOperation == constants.CERT_REQ_OPERATION:

            # if a certReq is READY but its MD5 is changed, it must be put down to EMPTY
            # becauase this means the xml file is changed (during upgrade)
            if certreq_state_string == constants.CERTREQ_STATE['READY']:

                saved_md5, calc_md5 = restAPIutil.readAndCalculateXmlMd5(secretItem)
                if saved_md5 != calc_md5:
                    common.log(constants.LOG_LEVEL_INFO, \
                        f"__getCertReqSecretsAndFillGlobalData; {globalData.tagOperationForMessages} operation - xml changed - {secret_name} set back to EMPTY - FORCE RESTART")
                    # reset state
                    certreq_state_string = constants.CERTREQ_STATE['EMPTY']
                    
                    # TODO
                    # is there a way to check if the helm update already initiate a restart ?

                    # force restart
                    globalData.forceRestartForUpgrade = True

        # UPGRADE_OPERATION end

        certSecretsTotalNum += 1
        # check the state

        # for initial install operations only cert. req. secrets with certReqState field = empty are considered
        if globalData.typeOfOperation == constants.CERT_REQ_OPERATION:
            if certreq_state_string == constants.CERTREQ_STATE['READY']:
                certSecretsInReadyStateNum += 1
                common.log(constants.LOG_LEVEL_DEBUG, \
                    f"__getCertReqSecretsAndFillGlobalData; {globalData.tagOperationForMessages} operation and FOUND certRequest secret = {secret_name} for service = {service_name} in ready state : NOT inserted in global data")
                continue

        # for cron check operations all cert. req. secrets must have certReqState field = ready, i.e. I.I. already done
        elif globalData.typeOfOperation == constants.CRON_CHECK_OPERATION:
            # TODO : could be possible to continue also for EMPTY state ?
            if certreq_state_string == constants.CERTREQ_STATE['EMPTY']:
                common.log(constants.LOG_LEVEL_DEBUG, \
                    f"__getCertReqSecretsAndFillGlobalData; {globalData.tagOperationForMessages} operation and FOUND certRequest secret = {secret_name} for service = {service_name} in empty state : exit ... ")
                globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
                return False

            # check if there is an upgrade not yet fulfilled
            # in the case the state is READY but the XML is changed, an upgrade operation will manage it
            if certreq_state_string == constants.CERTREQ_STATE['READY']:

                saved_md5, calc_md5 = restAPIutil.readAndCalculateXmlMd5(secretItem)
                if saved_md5 != calc_md5:
                    common.log(constants.LOG_LEVEL_DEBUG, \
                        f"__getCertReqSecretsAndFillGlobalData; {globalData.tagOperationForMessages} operation and FOUND certRequest secret = {secret_name} for service = {service_name} in updating situation : exit ... ")
                    globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
                    return False            

            # normal condition, we reach this point if no return
            certSecretsInReadyStateNum += 1

        else:
            common.log(constants.LOG_LEVEL_WARNING, \
                "__getCertReqSecretsAndFillGlobalData; kind of operation NOT recognized: exit ... ")
            globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
            return False
                     
        # save the name of certReq secret
        globalData.cerReqNameList.append(secret_name)

        # check if exist a script field and copy it into file system
        if constants.SECRET_CERTREQSCRIPT in secretItem.data:
            common.log(constants.LOG_LEVEL_INFO, " __getCertReqSecretsAndFillGlobalData: pre-start script found for  %s" % secret_name)
            certreq_script = secretItem.data[constants.SECRET_CERTREQSCRIPT]

	    # check if its an empty file
            if len(certreq_script) == 0:
                common.log(constants.LOG_LEVEL_DEBUG, " __getCertReqSecretsAndFillGlobalData: pre-start script is empty")
            else:
                # decode string
                certreq_script_string = common.decodeString(certreq_script)
                scriptFullFiilename = constants.CRED_DATA_PRESTART_SCRIPT_FOLDER + secret_name + ".sh"
                common.log(constants.LOG_LEVEL_DEBUG, " __getCertReqSecretsAndFillGlobalData: pre-start script name  %s" % scriptFullFiilename)
                common.writeTextFile(scriptFullFiilename, certreq_script_string)
                common.setExecutableOnFile(scriptFullFiilename)
            
        # read xml files and copy to file system
        xmlFullFiilename = constants.CRED_DATA_XMLFILES_FOLDER + certreq_xmlname_string
        common.writeTextFile(xmlFullFiilename, certreq_data_string)
        # modify xml file
        preprocXML.preprocxml(service_name, xmlFullFiilename, xmlFullFiilename)
        #
        if constants.LOG_DEBUG_FLAG:
            print("__getCertReqSecretsAndFillGlobalData: file " + xmlFullFiilename)
            #f = open(xmlFullFiilename, 'r')
            #print(f.read())
            #f.close()

        # parse XML
        xmlParser.parser(certreq_data_string)
        # add certReq name and calculate the number of tls secrets that have to exist and that refer to this cert. req. secret
        
        # find how many tlsSecrets are needed (looking xml parse result)
        theoreticalTlsSecretsList = []
        theoreticalNumOfTlsSecrets = 0
        for idx, item in enumerate(globalData.tlsItemsList):
            if item.getCertSecretName() == "NEW":
                if constants.LOG_DEBUG_FLAG:
                    print (" __getCertReqSecretsAndFillGlobalData: inside for to calculate theoreticalNumOfTlsSecrets; item (secret name) = %s, item (TlsType) = %s, item (TlsLocation) = %s" \
                           % (item.getCertSecretName(), item.getTlsType(), item.getTlsLocation())) 
                item.setCertSecretName(secret_name)
                globalData.tlsItemsList[idx] = item
                # more items can have the same tlsLocation and refer to the same tls secret
                if item.getTlsType() == constants.TLSSTORE_TYPE['FILE'] and not item.getTlsLocation() in theoreticalTlsSecretsList:
                    theoreticalNumOfTlsSecrets += 1
                    theoreticalTlsSecretsList.append(item.getTlsLocation())           
        common.log(constants.LOG_LEVEL_DEBUG, " __getCertReqSecretsAndFillGlobalData: theoric number of tls secrets is %s for cert. req. secret %s in service %s" % (theoreticalNumOfTlsSecrets, secret_name, service_name))
        
        # get the number of tls secrets that really exist and that refer to this cert. req. secret
        # tlsSecretsLabel = service_name + "-certreq-secret" (in case of more than one cert. req. secret this assignment does not work)
        retTlsSecretsList = restAPIsecretUtil.loadTlsSecretsForCertReqSecret(secret_name)

        realNumOfTlsSecrets = len(retTlsSecretsList.items)
        common.log(constants.LOG_LEVEL_DEBUG, \
            " __getCertReqSecretsAndFillGlobalData: real number of tls secrets is %s for cert. req. secret %s in service %s" % (realNumOfTlsSecrets, secret_name, service_name))
        
        # compare real number and theoric number
        if theoreticalNumOfTlsSecrets != realNumOfTlsSecrets:
            common.log(constants.LOG_LEVEL_WARNING, \
                "__getCertReqSecretsAndFillGlobalData real number and theoric number of tls secrets are different for cert. req. secret %s in service %s: exit ..." % (secret_name, service_name))
            globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
            return False
      
        # create a list with names of tls secrets relative to the cert. req. secret
        listTlsSecretsNames = []
        for i in range(realNumOfTlsSecrets):
            tlsSecretName = retTlsSecretsList.items[i].metadata.name
            listTlsSecretsNames.append(tlsSecretName)
        common.log(constants.LOG_LEVEL_DEBUG, \
            " __getCertReqSecretsAndFillGlobalData: list of names of tls secrets is %s for cert. req. secret %s for service %s" % (listTlsSecretsNames, secret_name, service_name))
    
        # add each tlsSecretName to globalData
        # more than one entry in globalData can have the same tlsSecretName
        # various kind of operation must be considered              

        # for INITIAL INSTALL or UPGRADE operation 
        if globalData.typeOfOperation == constants.CERT_REQ_OPERATION:

            listTlsSecretsNamesIterator = 0
            location = ""
            for idx, item in enumerate(globalData.tlsItemsList):
                # for each item in tlsItemsList, find a tlsSecret to associate with it
                if item.getCertSecretName() == secret_name:
                    if item.getTlsType() == constants.TLSSTORE_TYPE['FILE'] and item.getTlsSecretName() == "":
                        item.setTlsSecretName(listTlsSecretsNames[listTlsSecretsNamesIterator])
                        location = item.getTlsLocation()
                        # any other item referring the same location must be assiciated with the same tlsSecret
                        for idy in range(idx + 1, len(globalData.tlsItemsList)):
                            if globalData.tlsItemsList[idy].getTlsLocation() == location and globalData.tlsItemsList[idy].getCertSecretName() == secret_name:
                                globalData.tlsItemsList[idy].setTlsSecretName(listTlsSecretsNames[listTlsSecretsNamesIterator])
                        listTlsSecretsNamesIterator += 1
                    elif item.getTlsType() != constants.TLSSTORE_TYPE['FILE']:
                        item.setTlsSecretName(constants.SECRET_NONESTATE)
                    globalData.tlsItemsList[idx] = item
                    
        # for CRON CHECK operation
        elif globalData.typeOfOperation == constants.CRON_CHECK_OPERATION:
            # scan the list of tls secrets
            locationString = ""
            for i in range(realNumOfTlsSecrets):
                tlsSecretName = retTlsSecretsList.items[i].metadata.name
                location =  retTlsSecretsList.items[i].data[constants.SECRET_TLSSTORELOCATION]
                locationString = common.decodeString(location)
                # look for all entries in globaldata that have the same location of the tls secret found above
                for idx, item in enumerate(globalData.tlsItemsList):
                    if item.getCertSecretName() == secret_name:
                        if item.getTlsType() == constants.TLSSTORE_TYPE['FILE'] and item.getTlsSecretName() == "" and item.getTlsLocation() == locationString:
                            item.setTlsSecretName(tlsSecretName)
                        elif item.getTlsType() != constants.TLSSTORE_TYPE['FILE']:
                            item.setTlsSecretName(constants.SECRET_NONESTATE)
                        # TODO what if a tlsSecret is "New" ? is is not more managed
                        globalData.tlsItemsList[idx] = item 

    # end of loop for each certReqSecret to retrieve all data
         
    common.log(constants.LOG_LEVEL_DEBUG, \
        "__getCertReqSecretsAndFillGlobalData; number of certReq secrets in ready state = %d for service = %s" % \
            (certSecretsInReadyStateNum, service_name))
    common.log(constants.LOG_LEVEL_DEBUG, \
        "__getCertReqSecretsAndFillGlobalData; total number of certReq secrets = %d for service = %s" % \
            (certSecretsTotalNum, service_name))
        
    # if no EMPTY state : nothing to do
    if globalData.typeOfOperation == constants.CERT_REQ_OPERATION:    
        if certSecretsInReadyStateNum == certSecretsTotalNum:
            common.log(constants.LOG_LEVEL_WARNING, \
                "__getCertReqSecretsAndFillGlobalData : %s operation and ALL certRequest secrets for service = %s are already in ready state ... exit ..." % \
                    (globalData.tagOperationForMessages, service_name))
            globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_OK

            return False
    
    # INITIAL INSTALL operation
    # each entry in globalData is relative to an empty tls secret, i.e. a tls secret that has still 
    # tlsStoreLocation, tlsStoreType and tlsStoreData fields set to "none"
    # the value of the above fields will be updated after cli java execution.
    # Therefore for each tlsLocation in globalData the relative empty file folder is created in file system
    # it is necessary to let cli java run
    if globalData.typeOfOperation == constants.CERT_REQ_OPERATION:
        for item in globalData.tlsItemsList:
            if item.tlsType == constants.TLSSTORE_TYPE['FILE']:
                common.createFileFolder(item.tlsLocation)
                
    # CRON CHECK operation
    # each entry in globalData is relative to a key/trust store file already generated.
    # Therefore for each tlsLocation in globalData the relative file is created in file system and the relative MD5 is calculated
    # These file are the initial certificates files to let cli java run
    if globalData.typeOfOperation == constants.CRON_CHECK_OPERATION:
        
        tlsSecretsNamesList = []
        certReqSecretsNamesList = []
        retTlsSecretsList = []
        
        for index, element in enumerate(globalData.tlsItemsList):
            certReqSecretName =  element.getCertSecretName()

            common.log(constants.LOG_LEVEL_DEBUG, f"__getCertReqSecretsAndFillGlobalData: CRON CHECK index {index} certReqSecretName = {certReqSecretName}")
            
            if certReqSecretName not in certReqSecretsNamesList and certReqSecretName != "" and element.getTlsType() == constants.TLSSTORE_TYPE['FILE']:
                certReqSecretsNamesList.append(certReqSecretName)
                
                # get all tls secrets that are relative to the current cert req secret
                retTlsSecretsList = restAPIsecretUtil.loadTlsSecretsForCertReqSecret(certReqSecretName)

                realNumOfTlsSecrets = len(retTlsSecretsList.items)
                
                for idx, item in enumerate(globalData.tlsItemsList):
                    tlsSecretName = item.getTlsSecretName()
                    if tlsSecretName not in tlsSecretsNamesList and item.getTlsType() == constants.TLSSTORE_TYPE['FILE'] and \
                            item.getCertSecretName() == certReqSecretName:
                        tlsSecretsNamesList.append(tlsSecretName)
                
                        # get data for the corresponding tls secret 
                        tlsData = constants.SECRET_NONESTATE
                        for i in range(realNumOfTlsSecrets):
                            name = retTlsSecretsList.items[i].metadata.name
                            if tlsSecretName == name:
                                tlsData = retTlsSecretsList.items[i].data[constants.SECRET_TLSSTOREDATA]
                                break
                
                        #prepare data
                        filenameString = item.getTlsLocation()
                
                        # write file for keyStore/TrustStore in file system
                        common.writeBinaryFile(filenameString, tlsData)
                        # calculate/write MD5 for the file in globalData
                        fileMD5 = common.calculateFileMD5(filenameString) 
                        item.setTlsMD5(fileMD5)
                        # for all entries relative to the same tlsLocation (same tlsSecretName) set the same value for MD5
                        for idy in range(idx + 1, len(globalData.tlsItemsList)):
                            if globalData.tlsItemsList[idy].getTlsLocation() == filenameString and globalData.tlsItemsList[idy].getTlsType() == constants.TLSSTORE_TYPE['FILE'] \
                                    and globalData.tlsItemsList[idy].getCertSecretName() == certReqSecretName:
                                globalData.tlsItemsList[idy].setTlsMD5(fileMD5)
                        globalData.tlsItemsList[idx] = item              

    # creation of CLR folder (not managed , only to prepare folders for credentialmanagercli)
    for item in globalData.tlsItemsList:
        if item.tlsType == constants.TLSSTORE_TYPE['CRLFILE']:
            common.log(constants.LOG_LEVEL_DEBUG, "__getCertReqSecretsAndFillGlobalData: create CRL file folder: %s " % item.tlsLocation )
            common.createFileFolder(item.tlsLocation)
        if item.tlsType == constants.TLSSTORE_TYPE['CRLFOLDER']:
            common.log(constants.LOG_LEVEL_DEBUG, "__getCertReqSecretsAndFillGlobalData: create CRL  folder: %s " % item.tlsLocation )
            common.createFolder(item.tlsLocation)

    debugList = globalData.listGlobalData()
    for i in debugList:
        common.log(constants.LOG_LEVEL_DEBUG, i)

    return True
     # end of function __getCertReqSecretsAndFillGlobalData
                

###########################################
# __prepareDataForCli
#
# - preprocessing/parsing of file CredM-CLI-CertRequest.xml
# - read cli certs secrets and copy on file system (if not already present)
# - calculate md5 for keyStore and trustStore of cli 
#
# in: none
# out: True/False
###########################################
def __prepareDataForCli():
    
    # modify cli xml file 
    preprocXML.preprocxml("CliApplication", constants.CRED_CLI_XML_FILE_PATH, constants.CRED_CLI_XML_FILE_PATH)
    
    #read from Cli App XML 
    certreq_data_string = common.readTextFile(constants.CRED_CLI_XML_FILE_PATH)
    #if constants.LOG_DEBUG_FLAG:
    #    print("__prepareDataForCli; CredM-CLI-CertRequest.xml after preproc. : %s" % certreq_data_string)
    
    # parse XML
    ret = xmlParser.parserCli(certreq_data_string)
    common.log(constants.LOG_LEVEL_DEBUG, "__prepareDataForCli, for cli keyStore path = %s, trustStore path = %s" % (globalData.cliKeyStoreLocation, globalData.cliTrustStoreLocation))
    if ret == False:
        common.log(constants.LOG_LEVEL_WARNING, "__prepareDataForCli; parserCli returned NOT OK ... exit ... ")
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return ret
    
    calcMD5 = False
    if common.doesFileExist(globalData.cliKeyStoreLocation) and common.doesFileExist(globalData.cliTrustStoreLocation):
        common.log(constants.LOG_LEVEL_DEBUG, "__prepareDataForCli : in file system keyStore and TrustStore for Cli App already present but we get the most recent versions from secrets")
    else:
        common.log(constants.LOG_LEVEL_DEBUG, "__prepareDataForCli : in file system keyStore and TrustStore for Cli App NOT present yet")
                
    # already created (during cli installation) the folders for keystore and trustore of cli (necessary to run cli java) ... however ...
    # in case of cron check .. already created.
    common.createFileFolder(globalData.cliKeyStoreLocation)
    common.createFileFolder(globalData.cliTrustStoreLocation)
        
    # read tls secrets of cli
    result, retSecretsList = restAPIsecretUtil.loadTlsSecretsForCli()
    if not result:
        common.log(constants.LOG_LEVEL_WARNING, "__prepareDataForCli : loadTlsSecretsForCli return false : exit ...")
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return False
        
    cliStore1 = retSecretsList.items[0]
    tlsLocation1 = cliStore1.data[constants.SECRET_TLSSTORELOCATION]
    tlsLocationString1 = common.decodeString(tlsLocation1)
    tlsStoreType1 = cliStore1.data[constants.SECRET_TLSSTORETYPE]
    tlsStoreTypeString1 = common.decodeString(tlsStoreType1)
    cliStore2 = retSecretsList.items[1]
    tlsLocation2 = cliStore2.data[constants.SECRET_TLSSTORELOCATION]
    tlsLocationString2 = common.decodeString(tlsLocation2)
    tlsStoreType2 = cliStore2.data[constants.SECRET_TLSSTORETYPE]
    tlsStoreTypeString2 = common.decodeString(tlsStoreType2)
    # three situations are possible:
    #   1) tlsStoreLocation = tlsStoreType = "none" for both secrets : certs never generated.
    #      Update tlsStoreLocation immediately for both secrets, instead tlsStoreData and finally tlsStoreType will be updated 
    #      after java cli execution and after that cli certificates have been generated.
    #   2) tlsStoreLocation and tlsStoreType != "none" for both secrets : certs already generated.
    #      Put in file system keystore and truststore for cli, calculate MD5.
    #   3) tlsStoreLocation != "none" and tlsStoreType = "none" for both secrets. Another instance of credm controller
    #      found situation 1) and it is generating cli certifiactes. you Exit from the rest API. If it is a rest api for installation
    #      it will be executed again after a short wait. 
    #   4) in all other possible situations you Exit for the rest API. If it is a rest api for installation
    #      it will be executed again after a short wait.
    if constants.LOG_DEBUG_FLAG:
        print("__prepareDataForCli : tls location data in first tls secret = %s " % tlsLocationString1)
        print("__prepareDataForCli : tls location data in second tls secret = %s " % tlsLocationString2)

    if tlsLocationString1 == constants.SECRET_NONESTATE and tlsStoreTypeString1 == constants.SECRET_NONESTATE \
           and tlsLocationString2 == constants.SECRET_NONESTATE and tlsStoreTypeString2 == constants.SECRET_NONESTATE:
        # let's suppose both tls secrets not valid (empty) => situation 1)
        # - this case is possible for i.i. operations normally
        # - this case is possible for cron check operations only in transition from enabling state to enabled state
        common.log(constants.LOG_LEVEL_DEBUG, "__prepareDataForCli : tls secrets for cli are still empty")
        tlsLocationString1 = globalData.cliKeyStoreLocation
        tlsLocationString2 = globalData.cliTrustStoreLocation
        secretName1 = cliStore1.metadata.name 
        secretName2 = cliStore2.metadata.name
        cliStore1.data[constants.SECRET_TLSSTORELOCATION] = common.encodeString(tlsLocationString1)
        cliStore2.data[constants.SECRET_TLSSTORELOCATION] = common.encodeString(tlsLocationString2)
        # tlsStoreData of tls secret will be updated after java cli execution
        # tlsStoreType will be updated last after java cli execution (cli certificates generation)
        # update TLS secrets
        k8sApiInterface.updateSecretData(secretName1, constants.NAMESPACE, cliStore1)
        k8sApiInterface.updateSecretData(secretName2, constants.NAMESPACE, cliStore2)
    elif tlsLocationString1 != constants.SECRET_NONESTATE and tlsStoreTypeString1 != constants.SECRET_NONESTATE \
           and tlsLocationString2 != constants.SECRET_NONESTATE and tlsStoreTypeString2 != constants.SECRET_NONESTATE:
        # this is the normal case for cron check operations
        # let's suppose both cli tls secrets are valid => situation 2)
        common.log(constants.LOG_LEVEL_DEBUG, "__prepareDataForCli : cli tls secrets contain already valid certificates")
            
        calcMD5 = True
            
        tlsData1 = cliStore1.data[constants.SECRET_TLSSTOREDATA]
        tlsData2 = cliStore2.data[constants.SECRET_TLSSTOREDATA]
        # write keyStore and TrustStore in file system
        common.writeBinaryFile(tlsLocationString1, tlsData1)
        common.writeBinaryFile(tlsLocationString2, tlsData2)
    elif tlsLocationString1 != constants.SECRET_NONESTATE and tlsStoreTypeString1 == constants.SECRET_NONESTATE \
           and tlsLocationString2 != constants.SECRET_NONESTATE and tlsStoreTypeString2 == constants.SECRET_NONESTATE:
        # let's suppose we are in transition => situation 3)
        common.log(constants.LOG_LEVEL_WARNING, "__prepareDataForCli : another credm controller instance (replica) is generating cli certificates : exit ... ")
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return False
    else:
        # let's suppose we are in situation 4)
        common.log(constants.LOG_LEVEL_WARNING, "__prepareDataForCli : found ambiguos combination for values of tlsStoreLocation/tlsStoreType in cli secrets : exit ... ")
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return False
    
    # calculate MD5 hash for Cli keyStore and Cli TrustStore files
    if calcMD5 == True:
        globalData.cliKeyStoreMD5 = common.calculateFileMD5(globalData.cliKeyStoreLocation)
        globalData.cliTrustStoreMD5 = common.calculateFileMD5(globalData.cliTrustStoreLocation)
        if constants.LOG_DEBUG_FLAG:
            print("__prepareDataForCli : Before cli java execution MD5 hash for Cli keyStore = %s" % globalData.cliKeyStoreMD5)
            print("__prepareDataForCli : Before cli java execution MD5 hash for Cli TrustStore = %s" % globalData.cliTrustStoreMD5)    
            
    # end function
    return True
    
    
###########################################
# __updateDataForCli
#
# - update tls secrets for cli if it is necessary
#
# in: none
# out: True/False
###########################################
def __updateDataForCli():        
    
    if not common.doesFileExist(globalData.cliKeyStoreLocation):
        common.log(constants.LOG_LEVEL_WARNING, "__updateDataForCli; cli KeyStore does not exist in file system: exit ...")
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return False    
    cliKeyStoreMD5 = common.calculateFileMD5(globalData.cliKeyStoreLocation)
    if not common.doesFileExist(globalData.cliTrustStoreLocation):
        common.log(constants.LOG_LEVEL_WARNING, "__updateDataForCli; cli TrustStore does not exist in file system: exit ...")
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return False 
    cliTrustStoreMD5 = common.calculateFileMD5(globalData.cliTrustStoreLocation)
    if constants.LOG_DEBUG_FLAG:
        print("__updateDataForCli : After cli java execution MD5 hash for Cli keyStore = %s" % cliKeyStoreMD5)
        print("__updateDataForCli : After cli java execution MD5 hash for Cli TrustStore = %s" % cliTrustStoreMD5)
        
    if cliKeyStoreMD5 == globalData.cliKeyStoreMD5 and cliTrustStoreMD5 == globalData.cliTrustStoreMD5:
       common.log(constants.LOG_LEVEL_DEBUG, "__updateDataForCli : After cli java execution Cli keyStore/TrustStore have not changed ... nothing to update") 
       return True
   
    # read tls secrets of cli
    result, retSecretsList = restAPIsecretUtil.loadTlsSecretsForCli()
    if not result:
        common.log(constants.LOG_LEVEL_WARNING, "__updateDataForCli : loadTlsSecretsForCli return false : exit ...")
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return False
        
    cliStore1 = retSecretsList.items[0]
    tlsLocation1 = cliStore1.data[constants.SECRET_TLSSTORELOCATION]
    tlsLocationString1 = common.decodeString(tlsLocation1)
    
    cliStore2 = retSecretsList.items[1]
    tlsLocation2 = cliStore2.data[constants.SECRET_TLSSTORELOCATION]
    tlsLocationString2 = common.decodeString(tlsLocation2)

    # Note: in this point of code tlsLocationString read from cli tls secret
    #       is always different from "none"  
    
    # WARNING
    ret = True
    if cliKeyStoreMD5 != globalData.cliKeyStoreMD5:
        common.log(constants.LOG_LEVEL_DEBUG, "__updateDataForCli : After cli java execution Cli keyStore has changed. Updating the relative tls secret")
        ret = __updateTlsSecretForCli(cliStore1, cliStore2, tlsLocationString1, tlsLocationString2, globalData.cliKeyStoreLocation)
        
    # WARNING
    if ret == True: 
        if cliTrustStoreMD5 != globalData.cliTrustStoreMD5:
            common.log(constants.LOG_LEVEL_DEBUG, "__updateDataForCli : After cli java execution Cli TrustStore has changed. Updating the relative tls secret")
            ret = __updateTlsSecretForCli(cliStore1, cliStore2, tlsLocationString1, tlsLocationString2, globalData.cliTrustStoreLocation)
    else:
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
    
    # end function
    return ret


###########################################
# __updateTlsSecretForCli
#
# - update tls secrets for cli 
#
# in: cliStore1 - first tls secret for cli
#     cliStore2 - second tls secret for cli
#     tlsLocationString1 - decoded tlsLocation of cliStore1
#     tlsLocationString2 - decoded tlsLocation of cliStore2
#     fileSystemLocation - location in file system of KeyStore or TrustStore for cli
# out: True/False
###########################################
def __updateTlsSecretForCli(cliStore1, cliStore2, tlsLocationString1, tlsLocationString2, fileSystemLocation):
    
    # Note: in this point of code tlsLocationString read from cli tls secret
    #       is always different from "none"
     
    if tlsLocationString1 == fileSystemLocation:
        secretName = cliStore1.metadata.name 
        # update some fields : tlsStoreType and tlsStoreData
        rawdata = common.readFileToBase64(fileSystemLocation)
        cliStore1.data[constants.SECRET_TLSSTOREDATA] = rawdata
        tlsTypeString = constants.TLSSTORE_TYPE['FILE']   
        cliStore1.data[constants.SECRET_TLSSTORETYPE] = common.encodeString(tlsTypeString)  
        # update TLS secrets
        k8sApiInterface.updateSecretData(secretName, constants.NAMESPACE, cliStore1)
    elif tlsLocationString2 == fileSystemLocation:
        secretName = cliStore2.metadata.name
        # update some fields : tlsStoreType and tlsStoreData
        rawdata = common.readFileToBase64(fileSystemLocation)
        cliStore2.data[constants.SECRET_TLSSTOREDATA] = rawdata
        tlsTypeString = constants.TLSSTORE_TYPE['FILE']  
        cliStore2.data[constants.SECRET_TLSSTORETYPE] = common.encodeString(tlsTypeString)  
        # update TLS secrets
        k8sApiInterface.updateSecretData(secretName, constants.NAMESPACE, cliStore2)
    else:
        common.log(constants.LOG_LEVEL_WARNING, "___updateTlsSecretForCli : Location %s NOT FOUND in both cli tls secrets; exit ..." % fileSystemLocation)
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return False
    
    # end function
    return True


###########################################
# __updateDataForService
#
# - update tls secrets and cert. req. secrets for the service
#   in case of Initial Install
#
# in: none
# out: True/False
###########################################
def __updateDataForService(): 
    
    # WARNING
    # all entries in globalData are relative to the same service.
    # each entry in globalData is relative to a tls secret if tlsType = "file"
    # one or more entry in globalData for each tls secret
    # if MD5 changed read each tls secret and update the relative tlsStoreLocation, tlsStoreType and tlsStoreData fields
    # in case of INITIAL INSTALL OPERATION the initial value for MD5 is "" (empty)
    tlsSecretsNamesList = []
    for idx, item in enumerate(globalData.tlsItemsList):
        tlsSecretName = item.getTlsSecretName()
        # find all tlsSecret related to a file
        if tlsSecretName not in tlsSecretsNamesList and item.getTlsType() == constants.TLSSTORE_TYPE['FILE']:
            common.log(constants.LOG_LEVEL_DEBUG, f"__updateDataForService; item {idx} name {tlsSecretName}") 

            tlsSecretsNamesList.append(tlsSecretName)

            filenameString = item.getTlsLocation()
            if not common.doesFileExist(filenameString):
                common.log(constants.LOG_LEVEL_WARNING, "__updateDataForService; file %s does not exist in file system for service %s: exit ... " % (filenameString, service_name))
                globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
                return False

            fileNewMD5 = common.calculateFileMD5(filenameString)           
            if fileNewMD5 != item.getTlsMD5():
                common.log(constants.LOG_LEVEL_DEBUG, "__updateDataForService; MD5 has changed for tls secret %s for service %s" % (tlsSecretName, service_name))
                
                # read a tls secret 
                tlsSecret = restAPIsecretUtil.loadSingleTlsSecret(tlsSecretName)

                # prepare data to update the secret
                encoded_filename = common.encodeString(filenameString)
                filetypeString = constants.TLSSTORE_TYPE['FILE']
                encoded_filetype = common.encodeString(filetypeString)
                rawdata = common.readFileToBase64(filenameString)
                tlsSecret.data[constants.SECRET_TLSSTORELOCATION] = encoded_filename
                tlsSecret.data[constants.SECRET_TLSSTORETYPE] = encoded_filetype
                tlsSecret.data[constants.SECRET_TLSSTOREDATA] = rawdata
        
                # update a tls secret
                k8sApiInterface.updateSecretData(tlsSecretName, constants.NAMESPACE, tlsSecret)
    
    # WARNING
    # a service can have more than one cert. req. secret
    # more than one entry in globalData can be relative to the same cert. req. secret
    # read each cert. req. secret and update the relative certReqState field
    # TO DO ONLY in case of INITIAL INSTALL OPERATION
    if globalData.typeOfOperation == constants.CERT_REQ_OPERATION:
        certReqSecretsNamesList = []
        for idx, item in enumerate(globalData.tlsItemsList):
            certReqSecretName = item.getCertSecretName()
            if not certReqSecretName in certReqSecretsNamesList and item.getTlsType() == constants.TLSSTORE_TYPE['FILE']:
                certReqSecretsNamesList.append(certReqSecretName)
        for name in certReqSecretsNamesList:
            # read a cert. req. secret 
            certReqSecret = restAPIsecretUtil.loadSingleCertReqSecret(name)

            # prepare data to update the secret
            certreqStateString = constants.CERTREQ_STATE['READY']
            certReqSecret.data[constants.SECRET_CERTREQSTATE] = common.encodeString(certreqStateString)

            # 
            # update MD5 for xml file
            #
            certreq_data = certReqSecret.data[constants.SECRET_CERTREQDATA]
            certreq_data_string = common.decodeString(certreq_data)
            calc_md5 =  common.calculateStringMD5(certreq_data_string)
            if certreq_data_string != calc_md5:
                common.log(constants.LOG_LEVEL_DEBUG, f"__updateDataForService; certReqSecret {name} new  XML MD5 {calc_md5}")
                certReqSecret.data[constants.SECRET_CERTREQMD5] = common.encodeString(calc_md5)
            
            # update a cert. req. secret
            k8sApiInterface.updateSecretData(name, constants.NAMESPACE, certReqSecret)
        
    # end function
    return True


###########################################
# __resetDataForCliTlsSecrets
#
# - set to "none" the tlsStoreLocation and tlsStoreType data of cli tls secrets 
#   in all cases where install/cron restAPIs return with a NOT_OK condition.
#   The setting is done if during rest api execution it was foreseen to make
#   PKI generate new keystote/trustore for cli. 
#
# in: none
# out: True/False
###########################################
def __resetDataForCliTlsSecrets(): 
    
    # read tls secrets of cli
    result, retSecretsList = restAPIsecretUtil.loadTlsSecretsForCli()
    if not result:
        common.log(constants.LOG_LEVEL_WARNING, "__resetDataForCliTlsSecrets : loadTlsSecretsForCli return false : exit ...")
        globalData.globalResultToReturnFromApi = constants.RESULT_FROM_API_NOT_OK
        return False
        
    cliStore1 = retSecretsList.items[0]
    tlsLocation1 = cliStore1.data[constants.SECRET_TLSSTORELOCATION]
    tlsLocationString1 = common.decodeString(tlsLocation1)
    tlsStoreType1 = cliStore1.data[constants.SECRET_TLSSTORETYPE]
    tlsStoreTypeString1 = common.decodeString(tlsStoreType1)
    cliStore2 = retSecretsList.items[1]
    tlsLocation2 = cliStore2.data[constants.SECRET_TLSSTORELOCATION]
    tlsLocationString2 = common.decodeString(tlsLocation2)
    tlsStoreType2 = cliStore2.data[constants.SECRET_TLSSTORETYPE]
    tlsStoreTypeString2 = common.decodeString(tlsStoreType2)   
    
    if tlsLocationString1 != constants.SECRET_NONESTATE and tlsStoreTypeString1 == constants.SECRET_NONESTATE and tlsLocationString2 != constants.SECRET_NONESTATE and tlsStoreTypeString2 == constants.SECRET_NONESTATE:
        # we are in transition for cli certificates
        common.log(constants.LOG_LEVEL_DEBUG, "__resetDataForCliTlsSecrets; found transition state for cli tls secrets: reset data before returning from rest api")
    else:
        # we are NOT in transition for cli certificates
        common.log(constants.LOG_LEVEL_WARNING, "__resetDataForCliTlsSecrets; nothing to do for cli tls secrets before returning from rest api")
        return True
        
    tlsLocationString = constants.SECRET_NONESTATE
    tlsLocation = common.encodeString(tlsLocationString)
    cliStore1.data[constants.SECRET_TLSSTORELOCATION] = tlsLocation
    cliStore2.data[constants.SECRET_TLSSTORELOCATION] = tlsLocation
    secretName1 = cliStore1.metadata.name
    secretName2 = cliStore2.metadata.name
    
    # update TLS secrets
    k8sApiInterface.updateSecretData(secretName1, constants.NAMESPACE, cliStore1)
    k8sApiInterface.updateSecretData(secretName2, constants.NAMESPACE, cliStore2)
    
    return True   

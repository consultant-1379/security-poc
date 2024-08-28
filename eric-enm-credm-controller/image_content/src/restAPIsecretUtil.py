#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  REST SERVER  UTILITIES       #
#                               #
#  TO MANAGE SECRETS            #
#                               #
#################################

import constants
import common
import globalData
import k8sApiInterface


###########################################
#
# load a certReqSecret with name
#
# in: certReqSecretName (string)
# out: certReqSecret
###########################################
def loadSingleCertReqSecret(certReqSecretName):
                
    common.log(constants.LOG_LEVEL_DEBUG, "loadSingleCertReqSecret : name = %s " % certReqSecretName)

    # read a cert. req. secret 
    certReqSecret = k8sApiInterface.readSecretData(certReqSecretName, constants.NAMESPACE)

    if certReqSecret is None:
        common.log(constants.LOG_LEVEL_DEBUG, "loadSingleCertReqSecret : No secrets found ")
        return certReqSecret
        
    # check to add missing fields
    certReqSecret = __checkAndAddFieldsInCertReqSecret(certReqSecret)

    return certReqSecret


###########################################
#
# load a tlsSecret with name
#
# in: tlsSecretName (string)
# out: tlsSecret
###########################################
def loadSingleTlsSecret(tlsSecretName):

    common.log(constants.LOG_LEVEL_DEBUG, "loadSingleTlsSecret : name = %s " % tlsSecretName)

    # read a tls secret 
    tlsSecret = k8sApiInterface.readSecretData(tlsSecretName, constants.NAMESPACE)

    if tlsSecret is None:
        common.log(constants.LOG_LEVEL_DEBUG, "loadSingleTlsSecret : No secrets found ")
        return tlsSecret

    # check to add missing fields
    tlsSecret = __checkAndAddFieldsInTlsSecret(tlsSecret)

    return tlsSecret



###########################################
#
# load certReq secret for all services
#
# in: none
# out: certReqSecretList
###########################################
def loadAllCertReqSecrets():

    # read the list of 'cert-request' secrets with label certRequest: "true" 
    common.log(constants.LOG_LEVEL_DEBUG, "loadAllCertReqSecrets")  
    label_selector = constants.SECRET_LABEL_CERTREQUEST + " in (true)"
    retSecretsList = k8sApiInterface.readSecretsWithLabel(constants.NAMESPACE, label_selector)

    return retSecretsList


###########################################
#
# load certReq secret for service
#
# in: servicename (string)
# out: certReqSecretList
###########################################
def loadCertReqSecretsForService(service_name):

    # retrieve secret from label
    tlsSecretsLabel = service_name
    common.log(constants.LOG_LEVEL_DEBUG, "loadCertReqSecretsForService : value used for label = %s " % tlsSecretsLabel)
    label_selector = constants.SECRET_LABEL_SERVICENAME + " in ({servicename}), " + constants.SECRET_LABEL_CERTREQUEST + " in (true)"
    label_selector = label_selector.format(servicename=tlsSecretsLabel)
    retSecretsList = k8sApiInterface.readSecretsWithLabel(constants.NAMESPACE, label_selector)

    if len(retSecretsList.items) == 0:
        common.log(constants.LOG_LEVEL_DEBUG, "loadCertReqSecretsForService : No secrets found ")
        return retSecretsList

    # check and add fields
    for secretItem in retSecretsList.items:
        if constants.LOG_DEBUG_FLAG:
            print("loadCertReqSecretsForService : check fields for " + secretItem.metadata.name)
        # add secret fields if not present in deployment
        secretItem = __checkAndAddFieldsInCertReqSecret(secretItem)

    return retSecretsList


###########################################
#
# load tlsSecret for a given certReqSecret
#
# in: servicename (string)
# out: tlsSecretList
###########################################
def loadTlsSecretsForCertReqSecret(secret_name):

    tlsSecretsLabel = secret_name
    common.log(constants.LOG_LEVEL_DEBUG, " loadTlsSecretsForCertReqSecret: value used for label = %s " % (tlsSecretsLabel))
    label_selector = constants.SECRET_LABEL_CERTREQNAME + " in ({certreqname})"
    label_selector = label_selector.format(certreqname=tlsSecretsLabel)
    retSecretsList = k8sApiInterface.readSecretsWithLabel(constants.NAMESPACE, label_selector)

    if len(retSecretsList.items) == 0:
        common.log(constants.LOG_LEVEL_DEBUG, "loadTlsSecretsForCertReqSecret : No secrets found ")
        return retSecretsList

    # check and add fields
    for secretItem in retSecretsList.items:
        common.log(constants.LOG_LEVEL_DEBUG, "loadTlsSecretsForCertReqSecret : tlsSecret find: " + secretItem.metadata.name)
        # add secret fields if not present in deployment
        secretItem = __checkAndAddFieldsInTlsSecret(secretItem)

    return retSecretsList


###########################################
#
# load TlsSecrets for CLI
#
# in: none
# out: result (boolean)
# out: tlsSecretList
###########################################
def loadTlsSecretsForCli():

    # read tls secrets of cli
    tlsSecretsLabel = constants.CONTROLLER_NAME + "-certreq-secret"
    common.log(constants.LOG_LEVEL_DEBUG, "loadTlsSecretsForCli : value used for label of cli tls secrets  = %s " % tlsSecretsLabel)
    label_selector = constants.SECRET_LABEL_CERTREQNAME + " in ({certreqname})"
    label_selector = label_selector.format(certreqname=tlsSecretsLabel)
    retSecretsList = k8sApiInterface.readSecretsWithLabel(constants.NAMESPACE, label_selector)
    
    if len(retSecretsList.items) != 2:
        common.log(constants.LOG_LEVEL_WARNING, "loadTlsSecretsForCli : number of tls secrets found for cli app is NOT 2")
        return False, None
    
    # check and add fields
    for secretItem in retSecretsList.items:
        if constants.LOG_DEBUG_FLAG:
            print("loadTlsSecretsForCli : check fields for " + secretItem.metadata.name)
        secretItem = __checkAndAddFieldsInTlsSecret(secretItem)

    return True, retSecretsList


###########################################
#
# add secret fields not present in deployment for certReqSecret
#
# in: certReqSecret
# out: certReqSecret
###########################################
def __checkAndAddFieldsInCertReqSecret(secretItem):

    # if certReqState is not present in secret, add it with EMPTY state
    changeFlag, secretItem = __checkAndAddFieldsInSecret(secretItem, constants.SECRET_CERTREQSTATE, constants.CERTREQ_STATE['EMPTY'])

    if changeFlag and constants.LOG_DEBUG_FLAG:
        print("__checkAndAddFieldsInCertReqSecret : patched secret")
        print(secretItem)

    return secretItem


###########################################
#
# reset tlsSecret data (if any)
#
# in: tlsSecret
# out: tlsSecret
###########################################
def resetFieldsInTlsSecret(secretItem):
    
    changeFlag = False
    common.log(constants.LOG_LEVEL_DEBUG, "resetFieldsInTlsSecret: reset data field")

    if secretItem.data != None:
        # reset the fields
        if secretItem.data[constants.SECRET_TLSSTORELOCATION] != common.encodeString(constants.SECRET_NONESTATE):
            changeFlag = True
            secretItem.data[constants.SECRET_TLSSTORELOCATION] = common.encodeString(constants.SECRET_NONESTATE)
        if secretItem.data[constants.SECRET_TLSSTORETYPE] != common.encodeString(constants.SECRET_NONESTATE):
            changeFlag = True
            secretItem.data[constants.SECRET_TLSSTORETYPE] = common.encodeString(constants.SECRET_NONESTATE)
        if secretItem.data[constants.SECRET_TLSSTOREDATA] != common.encodeString(constants.SECRET_EMPTYDATA):
            changeFlag = True
            secretItem.data[constants.SECRET_TLSSTOREDATA] = common.encodeString(constants.SECRET_EMPTYDATA)

    if changeFlag and constants.LOG_DEBUG_FLAG:
        print("resetFieldsInTlsSecret : patched secret")
        print(secretItem)

    return secretItem


###########################################
# internal                                #
###########################################


###########################################
#
# add secret fields not present in deployment for certReqSecret
#
# in: certReqSecret
# out: certReqSecret
###########################################
def __checkAndAddFieldsInCertReqSecret(secretItem):

    # if certReqState is not present in secret, add it with EMPTY state
    changeFlag, secretItem = __checkAndAddFieldsInSecret(secretItem, constants.SECRET_CERTREQSTATE, constants.CERTREQ_STATE['EMPTY'])

    ret, secretItem = __checkAndAddFieldsInSecret(secretItem, constants.SECRET_CERTREQMD5, constants.SECRET_NONESTATE)
    if ret:
        changeFlag = True       
    
    if changeFlag and constants.LOG_DEBUG_FLAG:
        print("__checkAndAddFieldsInCertReqSecret : patched secret")
        print(secretItem)

    return secretItem


###########################################
#
# add secret fields not present in deployment for tlsSecret
#
# in: tlsSecret
# out: tlsSecret
###########################################
def __checkAndAddFieldsInTlsSecret(secretItem):

    #print(".........................checkAndAddFieldsInTlsSecret")
    #print(secretItem)
    #print(type(secretItem))
    
    changeFlag = False
    if secretItem.data == None:
        changeFlag = True
        common.log(constants.LOG_LEVEL_DEBUG, "__checkAndAddFieldsInTlsSecret: add data field")
        data = {}
        secretItem.data = data
    # check the fields to add them if not present
    ret, secretItem = __checkAndAddFieldsInSecret(secretItem, constants.SECRET_TLSSTORELOCATION, constants.SECRET_NONESTATE)
    if ret:
        changeFlag = True
    ret, secretItem = __checkAndAddFieldsInSecret(secretItem, constants.SECRET_TLSSTORETYPE, constants.SECRET_NONESTATE)
    if ret:
        changeFlag = True
    ret, secretItem = __checkAndAddFieldsInSecret(secretItem, constants.SECRET_TLSSTOREDATA, constants.SECRET_EMPTYDATA)
    if ret:
        changeFlag = True

    if changeFlag and constants.LOG_DEBUG_FLAG:
        print("__checkAndAddFieldsInTlsSecret : patched secret")
        print(secretItem)

    return secretItem


###########################################
#
# add secret fields not present in deployment
#
# in: secret
# in: field name (string)
# in: fieldData (string)
# out: change flag
# out: secret
###########################################
def __checkAndAddFieldsInSecret(secretItem, fieldName, fieldData):

    changeFlag = False
    if not fieldName in secretItem.data:
        changeFlag = True
        common.log(constants.LOG_LEVEL_DEBUG, f"__checkAndAddFieldsInSecret: add {fieldName} to secret")
        secretItem.data[fieldName] = common.encodeString(fieldData)
    return changeFlag, secretItem
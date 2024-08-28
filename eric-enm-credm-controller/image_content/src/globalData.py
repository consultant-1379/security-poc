#
# cENM Credemtialmanager Controller POD
#
# Ericsson - District11 - 2020
#

#################################
#                               #
#  GlobalData                   #
#                               #
#################################

import constants
import common

# cli app
cliTrustStoreLocation = ""
cliKeyStoreLocation = ""
cliKeyStoreMD5 = ""
cliTrustStoreMD5 = ""

# global result
globalResultToReturnFromApi = constants.RESULT_FROM_API_OK

# type Of Operation, i.e. Initial Install OR Cron Check
typeOfOperation = ""
# string to be returned with type of operation
tagOperationForMessages = ""
# flag to force restart in case of upgrade
forceRestartForUpgrade = False
   
cerReqNameList = []
tlsItemsList = []


# Python3 code here for creating class
class tlsMetadata:

    def __init__(self, tlsType, tlsLocation):
        self.tlsType = tlsType
        self.tlsLocation = tlsLocation
        self.certReqSecretName = ""
        self.tlsSecretName = ""
        self.tlsMD5 = ""

    def setCertSecretName(self, certReqSecretName):
        self.certReqSecretName = certReqSecretName

    def setTlsSecretName(self, tlsSecretName):
        self.tlsSecretName = tlsSecretName
            
    def setTlsMD5(self, tlsMD5):
        self.tlsMD5 = tlsMD5

    def getTlsType(self):
        return (self.tlsType)

    def getTlsLocation(self):
        return (self.tlsLocation)

    def getCertSecretName(self):
        return (self.certReqSecretName)

    def getTlsSecretName(self):
        return (self.tlsSecretName)

    def getTlsMD5(self):
        return(self.tlsMD5)

    def readItem(self):
        res = "tlsItem type: %s - certReqSecretName : %s - tlsSecretName: %s - location: %s - md5 %s" % \
            (self.getTlsType(), self.getCertSecretName(), self.getTlsSecretName(), self.getTlsLocation(), self.getTlsMD5())
        return res


def initGlobalData():
    del cerReqNameList[:]
    del tlsItemsList[:]
    
    # cliApp
    cliKeyStoreMD5 = ""
    cliTrustStoreMD5 = ""
    cliTrustStoreLocation = ""
    cliKeyStoreLocation = ""
    
    # global result
    globalResultToReturnFromApi = constants.RESULT_FROM_API_OK
    
    # type Of Operation, i.e. Initial Install OR Cron Check
    typeOfOperation = ""
    
    common.log(constants.LOG_LEVEL_DEBUG, "global data cleared")


def listGlobalData():
    str_list = []
    str_list.append("GLOBAL DATA:")
    for item in cerReqNameList:
        str_list.append("certReq secret: %s" % (item))
    for item in tlsItemsList:
        str_list.append(item.readItem())
    return str_list
